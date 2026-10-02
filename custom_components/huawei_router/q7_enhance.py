"""Q7 (MEDUSA2-BR80) 深度适配增强模块。

数据来源：2026-09-30 对 Q7 网线版固件的局域网 API 实测探测
（q7_recon/q7_probe_report.json，63 个端点确认存在，字段结构已验证）。

设计原则：
- 独立 DataUpdateCoordinator，只读端点并发拉取，单点失败不影响整体；
- 404 端点永久记入 missing 集合（固件能力差异），异常类错误保留重试；
- 写操作统一走 HuaweiApi.update_config（GET 完整对象 → 覆盖字段 → POST，
  自带字段校验，杜绝错误 payload 写入路由器）；
- 对主集成零侵入：sensor.py / switch.py 末尾各追加一次 setup 调用。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import Any, Final

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .client.huaweiapi import HuaweiApi
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 实测确认存在的只读端点（Q7 固件）
# ---------------------------------------------------------------------------
Q7_READ_ENDPOINTS: Final[dict[str, str]] = {
    "device_count": "api/system/device_count",
    "processstatus": "api/system/processstatus",
    "channelinfo": "api/ntwk/channelinfo",
    "repeaterstate": "api/ntwk/repeaterstate",
    "wlanmode": "api/system/wlanmode",
    "homesec_abfa": "api/ntwk/homesec_abfa",
    "homesec_stealnet": "api/ntwk/homesec_stealnet",
    "onlinestate": "api/system/onlinestate",
    "ethnegotiation": "api/ntwk/ethnegotiation",
    "sntp": "api/ntwk/sntp",
    "wlantimeswitch": "api/ntwk/wlantimeswitch",
    "wlan_time_switch_list": "api/ntwk/wlan_time_switch_list",
    "ledstatus": "api/hilink/ledstatus",
    # 可写开关端点也纳入轮询：CoordinatorEntity.should_poll=False，
    # 开关状态必须由协调器刷新才能跟随路由器侧变化（App/自动化修改）
    "ip6firewall_enable": "api/ntwk/ip6firewall_enable",
    "autoupgrade": "api/system/autoupgrade",
    "wansearchcontrol": "api/ntwk/wansearchcontrol",
    "wlanpowertimeswitch": "api/ntwk/wlanpowertimeswitch",
    "wlantimeaccelerate": "api/ntwk/wlanTimingAccelerate",
    "userbehavior": "api/system/userbehavior",
    # --- BE7 Pro (XIHE-BE72) 增量端点（2026-10-02 登录实测；Q7 上 404 自动跳过）---
    "smartvpn": "api/ntwk/smartvpn",
    "ethportmode": "api/ntwk/ethportmode",
    "hilinkwaninfo": "api/ntwk/hilinkwaninfo",
    "repeaterdiag": "api/ntwk/repeaterdiag",
}

# 可写端点（switch 用，字段均经 GET 确认存在）
# smartvpn 为 BE7 Pro 增量（{Enable,Type}，Q7 上 404 由 setup 预检跳过）
Q7_WRITE_ENDPOINTS: Final[dict[str, str]] = {
    "ledstatus": "api/hilink/ledstatus",
    "ip6firewall_enable": "api/ntwk/ip6firewall_enable",
    "autoupgrade": "api/system/autoupgrade",
    "wansearchcontrol": "api/ntwk/wansearchcontrol",
    "wlanpowertimeswitch": "api/ntwk/wlanpowertimeswitch",
    "wlantimeaccelerate": "api/ntwk/wlanTimingAccelerate",
    "userbehavior": "api/system/userbehavior",
    "smartvpn": "api/ntwk/smartvpn",
}

Q7_DOMAIN_KEY: Final = "q7_enhance_coordinator"


def _to_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "on", "yes", "enable", "enabled")
    return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
#   Q7EnhanceCoordinator
# ---------------------------------------------------------------------------
class Q7EnhanceCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Q7 扩展端点轮询协调器（只读）。"""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, api: HuaweiApi, interval: int) -> None:
        self._api = api
        self._entry = entry
        self._missing: set[str] = set()
        self._router_mac: str | None = None
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_q7_enhance",
            update_interval=timedelta(seconds=max(interval, 10)),
            always_update=True,
        )

    @property
    def router_mac(self) -> str | None:
        return self._router_mac

    @property
    def api(self) -> HuaweiApi:
        """路由器 API 客户端。"""
        return self._api

    def value(self, key: str) -> dict | list | None:
        """返回端点最近一次成功的 JSON 数据（None = 固件不支持/未成功）。"""
        data = self.data or {}
        return data.get(key)

    async def _async_update_data(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        prev = self.data or {}

        async def _read(key: str, path: str) -> None:
            try:
                resp = await self._api.get_endpoint_config(path)
                if resp.get("status") == 200 and resp.get("data") is not None:
                    results[key] = resp["data"]
                elif resp.get("status") == 404:
                    self._missing.add(key)
            except Exception as exc:  # noqa: BLE001
                # 网络抖动/单点超时：沿用上一轮数据，避免实体集体短暂 unavailable
                if key in prev:
                    results[key] = prev[key]
                _LOGGER.debug("Q7 端点 %s 读取失败: %s", key, exc)

        await asyncio.gather(
            *(
                _read(key, path)
                for key, path in Q7_READ_ENDPOINTS.items()
                if key not in self._missing
            )
        )

        if self._router_mac is None:
            self._router_mac = await self._async_resolve_router_mac()

        return results

    async def _async_resolve_router_mac(self) -> str | None:
        """从 lan_all 取主路由 LAN 口 MAC（作为设备归属标识补充）。"""
        try:
            resp = await self._api.get_endpoint_config("api/ntwk/lan_all")
            data = resp.get("data")
            if resp.get("status") == 200 and isinstance(data, list) and data:
                mac = data[0].get("MACAddress") or data[0].get("MacAddress")
                return mac if isinstance(mac, str) else None
        except Exception:  # noqa: BLE001
            pass
        return None

    # -- 写操作 ---------------------------------------------------------------
    async def set_flag(self, key: str, enabled: bool) -> None:
        """把布尔值写入可写端点的 Enable 字段。"""
        path = Q7_WRITE_ENDPOINTS.get(key)
        if not path:
            raise ValueError(f"Unknown Q7 writable endpoint: {key}")
        # update_config: GET 完整对象 → 覆盖字段 → POST（字段不存在会抛错，安全）
        await self._api.update_config(path, {"Enable": bool(enabled)}, action="update")
        # 写后路由器读取可能有短暂延迟，先本地落值防止 UI 闪回旧态，再异步校准
        data = (self.data or {}).get(key)
        if isinstance(data, dict):
            data["Enable"] = bool(enabled)
        self.async_update_listeners()
        await self.async_request_refresh()


# ---------------------------------------------------------------------------
#   设备信息（归属到主路由设备）
# ---------------------------------------------------------------------------
def _device_serial(main_coordinator: Any) -> str:
    """设备序列号（unique_id 的设备隔离锚点，多路由器并存必需）。"""
    try:
        info = main_coordinator.get_router_info(None)
    except Exception:  # noqa: BLE001
        info = None
    serial = getattr(info, "serial_number", None) if info else None
    return (str(serial) if serial else "UNKNOWN").strip().upper()


def _device_info(main_coordinator: Any) -> DeviceInfo | None:
    try:
        info = main_coordinator.get_router_info(None)
    except Exception:  # noqa: BLE001
        info = None
    if not info or not getattr(info, "serial_number", None):
        return None
    return DeviceInfo(
        identifiers={(DOMAIN, info.serial_number)},
        name=getattr(info, "name", None) or "Huawei Router",
        manufacturer="Huawei",
        model=getattr(info, "model", None),
        sw_version=str(getattr(info, "software_version", None) or ""),
    )


# ---------------------------------------------------------------------------
#   传感器
# ---------------------------------------------------------------------------
@dataclass
class Q7SensorDescription(SensorEntityDescription):
    """Q7 传感器描述。key = Q7_READ_ENDPOINTS 中的数据键。"""

    key: str = ""
    sub_key: str | None = None  # 数据 dict 内的字段（None = 整个对象做 attr）
    unit: str | None = None
    device_class: SensorDeviceClass | str | None = None
    state_class: SensorStateClass | str | None = None
    icon: str | None = None
    entity_category: EntityCategory | None = EntityCategory.DIAGNOSTIC


Q7_SENSORS: Final = [
    Q7SensorDescription(
        key="device_count", sub_key="ActiveDeviceNumbers",
        name="活跃设备数", icon="mdi:devices", state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="device_count", sub_key="UserNumber",
        name="已注册用户设备数", icon="mdi:account-multiple", state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="device_count", sub_key="HiLinkDevNum",
        name="智联设备数", icon="mdi:link-variant", state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="processstatus", sub_key="__cpu__",
        name="路由器 CPU 占用", unit=PERCENTAGE, icon="mdi:cpu-64-bit",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="processstatus", sub_key="__mem__",
        name="路由器内存占用", unit=PERCENTAGE, icon="mdi:memory",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="channelinfo", sub_key="NetChannelMode",
        name="信道模式", icon="mdi:wifi-strength-2",
    ),
    Q7SensorDescription(
        key="channelinfo", sub_key="NetStatus",
        name="网络状态", icon="mdi:network",
    ),
    Q7SensorDescription(
        key="channelinfo", sub_key="__ap_count__",
        name="Mesh AP 数量", icon="mdi:access-point",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="ethnegotiation", sub_key="__lan_up_count__",
        name="在线网口数", icon="mdi:ethernet",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="ledstatus", sub_key="Status",
        name="指示灯状态码", icon="mdi:led-on",
    ),
    Q7SensorDescription(
        key="repeaterstate", sub_key="signal",
        name="子路由回传信号", unit="dBm", icon="mdi:signal",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    Q7SensorDescription(
        key="wlanmode", sub_key="WLANMode",
        name="组网模式", icon="mdi:router-wireless",
    ),
    Q7SensorDescription(
        key="wlanmode", sub_key="ConnectState",
        name="组网连接状态", icon="mdi:lan-connect",
    ),
    Q7SensorDescription(
        key="homesec_abfa", sub_key="AbfaCount",
        name="防暴力破解拦截次数", icon="mdi:shield-lock", state_class=SensorStateClass.TOTAL,
    ),
    Q7SensorDescription(
        key="onlinestate", sub_key="CurrentVersion",
        name="固件版本", icon="mdi:chip",
        entity_category=None,
    ),
    Q7SensorDescription(
        key="onlinestate", sub_key="DownloadProcess",
        name="固件升级进度", unit=PERCENTAGE, icon="mdi:progress-download",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    # --- BE7 Pro 增量（Q7 上对应端点 404，数据驱动注册自动跳过）---
    Q7SensorDescription(
        key="hilinkwaninfo", sub_key="ConnState",
        name="智联上行连接状态", icon="mdi:lan-connect",
    ),
    Q7SensorDescription(
        key="hilinkwaninfo", sub_key="ConnType",
        name="智联上行类型", icon="mdi:ethernet",
    ),
    Q7SensorDescription(
        key="ethportmode", sub_key="Mode",
        name="网口模式", icon="mdi:ethernet",
    ),
]


class Q7Sensor(CoordinatorEntity[Q7EnhanceCoordinator], SensorEntity):
    entity_description: Q7SensorDescription

    def __init__(self, coordinator: Q7EnhanceCoordinator, entry: ConfigEntry, description: Q7SensorDescription, main_coordinator: Any) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = f"{DOMAIN}_q7_{_device_serial(main_coordinator)}_{description.key}_{description.sub_key}".replace(" ", "_").lower()
        self._attr_device_info = _device_info(main_coordinator)

    @property
    def available(self) -> bool:
        return self.coordinator.value(self.entity_description.key) is not None

    @staticmethod
    def _top_process(items: list[dict], field_name: str) -> float | None:
        # Q7 进程表首行 Name="Total" 即全局占用值（实测确认）；缺失时退回最大值
        for item in items:
            if isinstance(item, dict) and str(item.get("Name", "")).lower() == "total":
                value = _to_float(item.get(field_name))
                if value is not None:
                    return value
        values = [_to_float(i.get(field_name)) for i in items if isinstance(i, dict)]
        values = [v for v in values if v is not None]
        return max(values) if values else None

    @property
    def native_value(self) -> Any:
        data = self.coordinator.value(self.entity_description.key)
        desc = self.entity_description
        if data is None:
            return None
        sub = desc.sub_key
        if sub in ("__cpu__", "__mem__"):
            if not isinstance(data, list):
                return None
            return self._top_process(data, "CpuUsage" if sub == "__cpu__" else "MemUsage")
        if sub == "__ap_count__":
            wifi = data.get("WifiStatus") if isinstance(data, dict) else None
            return len(wifi) if isinstance(wifi, list) else None
        if sub == "__lan_up_count__":
            ports = data.get("ethintflist") if isinstance(data, dict) else None
            if isinstance(ports, list):
                return sum(1 for p in ports if isinstance(p, dict) and p.get("Status"))
            return None
        if isinstance(data, dict):
            value = data.get(sub)
            if desc.unit == "dBm":
                value = _to_float(value)
            elif desc.state_class in (SensorStateClass.MEASUREMENT, SensorStateClass.TOTAL):
                num = _to_float(value)
                value = num if num is not None else value
            return value
        return None

    @property
    def extra_state_attributes(self) -> dict | None:
        data = self.coordinator.value(self.entity_description.key)
        if data is None:
            return None
        key = self.entity_description.key
        if key == "processstatus" and isinstance(data, list):
            return {
                "processes": [
                    {"name": i.get("Name"), "cpu": i.get("CpuUsage"), "mem": i.get("MemUsage")}
                    for i in data if isinstance(i, dict)
                ]
            }
        if key == "channelinfo" and isinstance(data, dict):
            attrs: dict[str, Any] = {
                k: data.get(k)
                for k in ("ChannelDeploy", "HideChannelMode", "NetChannelMode", "NetStatus")
            }
            # 每 AP 每频段的信道与质量（实测：Status=质量分序列，Channel=当前信道）
            ap_list = data.get("WifiStatus")
            if isinstance(ap_list, list):
                summary = []
                for ap in ap_list:
                    if not isinstance(ap, dict):
                        continue
                    entry: dict[str, Any] = {"name": ap.get("Name"), "mac": ap.get("MacAddress")}
                    for band in ap.get("ChannelInfo", []) or []:
                        if isinstance(band, dict):
                            fb = band.get("FrequencyBand", "?")
                            entry[fb] = {
                                "channel": band.get("Channel"),
                                "score": band.get("Status"),
                            }
                    summary.append(entry)
                attrs["aps"] = summary
            return attrs
        if key == "repeaterstate" and isinstance(data, dict):
            return {k: data.get(k) for k in ("ssid", "connstate", "channel", "speed", "radio", "wifiConnectState")}
        if key == "ethnegotiation" and isinstance(data, dict):
            ports = data.get("ethintflist")
            if isinstance(ports, list):
                return {
                    "ports": [
                        {
                            "port": p.get("PortName") or p.get("diaplayName"),
                            "speed_mbps": p.get("Speed"),
                            "up": bool(p.get("Status")),
                        }
                        for p in ports if isinstance(p, dict)
                    ]
                }
            return None
        if key == "homesec_stealnet" and isinstance(data, dict):
            return {k: data.get(k) for k in ("StealNetModel", "AntiLeakageCapability")}
        if key == "device_count" and isinstance(data, dict):
            return {k: data.get(k) for k in ("LanActiveNumber", "HiLinkDevNum", "UserNumber", "ActiveDeviceNumbers")}
        if key == "sntp" and isinstance(data, dict):
            return {k: data.get(k) for k in ("CurrentLocalTime", "SntpIsSynchronizedStatus", "NTPServer1", "NTPServer2")}
        if key == "wlantimeswitch" and isinstance(data, dict):
            return {"datelist": data.get("datelist")}
        if key == "wlan_time_switch_list" and isinstance(data, dict):
            return {"maclist": data.get("maclist")}
        return None


async def async_setup_q7_sensors(
    hass: HomeAssistant,
    entry: ConfigEntry,
    main_coordinator: Any,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = await _get_or_create_q7_coordinator(hass, entry, main_coordinator)
    async_add_entities(
        [Q7Sensor(coordinator, entry, desc, main_coordinator) for desc in Q7_SENSORS],
        update_before_add=False,
    )

    # 智慧生活式 AP 卡片：每台 Mesh AP × 每频段一个信道传感器（动态发现，
    # 新 AP 上线自动补建，unique_id 以 MAC+频段为锚）
    known_aps: dict[str, bool] = {}

    def _discover() -> None:
        _discover_ap_entities(coordinator, entry, main_coordinator, known_aps, async_add_entities)

    _discover()
    entry.async_on_unload(coordinator.async_add_listener(_discover))


class Q7APSensor(CoordinatorEntity[Q7EnhanceCoordinator], SensorEntity):
    """每台 Mesh AP × 每频段：当前信道（附加质量分/信道列表属性）。"""

    def __init__(
        self,
        coordinator: Q7EnhanceCoordinator,
        entry: ConfigEntry,
        mac: str,
        ap_name: str | None,
        band: str,
        main_coordinator: Any,
    ) -> None:
        super().__init__(coordinator)
        self._mac = mac.upper()
        self._band = band
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}_q7_{_device_serial(main_coordinator)}_ap_{mac.replace(':', '').lower()}_{band.replace('.', '').lower()}"
        self._attr_device_info = _device_info(main_coordinator)
        self._attr_icon = "mdi:router-wireless"

    def _current(self) -> dict | None:
        ci = self.coordinator.value("channelinfo")
        if not isinstance(ci, dict):
            return None
        for ap in ci.get("WifiStatus") or []:
            if not isinstance(ap, dict) or (ap.get("MacAddress") or "").upper() != self._mac:
                continue
            for band in ap.get("ChannelInfo") or []:
                if isinstance(band, dict) and band.get("FrequencyBand") == self._band:
                    return band
        return None

    def _ap_name(self) -> str:
        ci = self.coordinator.value("channelinfo")
        if isinstance(ci, dict):
            for ap in ci.get("WifiStatus") or []:
                if isinstance(ap, dict) and (ap.get("MacAddress") or "").upper() == self._mac:
                    return ap.get("Name") or self._mac
        return self._mac

    @property
    def name(self) -> str | None:
        return f"{self._ap_name()} {self._band}"

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success and self._current() is not None

    @property
    def native_value(self) -> Any:
        band = self._current()
        if band is None:
            return None
        try:
            return int(band.get("Channel"))
        except (TypeError, ValueError):
            return band.get("Channel")

    @property
    def extra_state_attributes(self) -> dict | None:
        band = self._current()
        if band is None:
            return None
        return {
            "quality_score": band.get("Status"),
            "channel_list": band.get("ChannelList"),
            "mac": self._mac,
            "band": self._band,
        }


def _discover_ap_entities(
    coordinator: Q7EnhanceCoordinator,
    entry: ConfigEntry,
    main_coordinator: Any,
    known: dict[str, bool],
    async_add_entities: AddEntitiesCallback,
) -> None:
    """从 channelinfo.WifiStatus 发现 AP×频段并增量建实体。"""
    ci = coordinator.value("channelinfo")
    if not isinstance(ci, dict):
        return
    new: list[Q7APSensor] = []
    for ap in ci.get("WifiStatus") or []:
        if not isinstance(ap, dict):
            continue
        mac = (ap.get("MacAddress") or "").upper()
        if not mac:
            continue
        for band in ap.get("ChannelInfo") or []:
            fb = (band or {}).get("FrequencyBand")
            if not fb:
                continue
            uid = f"{mac}|{fb}"
            if uid not in known:
                known[uid] = True
                new.append(Q7APSensor(coordinator, entry, mac, ap.get("Name"), fb, main_coordinator))
    if new:
        async_add_entities(new, update_before_add=False)


# ---------------------------------------------------------------------------
#   开关
# ---------------------------------------------------------------------------
@dataclass
class Q7SwitchDescription(SwitchEntityDescription):
    key: str = ""            # Q7_WRITE_ENDPOINTS 键
    name: str | None = None
    icon: str | None = None


Q7_SWITCHES: Final = [
    # 注：LED（api/hilink/ledstatus）实测 Status=255，写入语义未知，
    # 为避免误写固件状态，只提供传感器展示；控制可临时用
    # huawei_router.api_set 服务（endpoint=ledstatus, data={"Status": 0/1}）。
    Q7SwitchDescription(key="ip6firewall_enable", name="IPv6 防火墙", icon="mdi:shield-half-full"),
    Q7SwitchDescription(key="autoupgrade", name="自动升级", icon="mdi:cloud-upload"),
    Q7SwitchDescription(key="wansearchcontrol", name="WAN 口自适应", icon="mdi:swap-horizontal"),
    Q7SwitchDescription(key="wlanpowertimeswitch", name="WiFi 定时节能", icon="mdi:wifi-clock"),
    Q7SwitchDescription(key="wlantimeaccelerate", name="WiFi 定时加速", icon="mdi:speedometer"),
    Q7SwitchDescription(key="userbehavior", name="上网行为统计", icon="mdi:chart-line"),
    # BE7 Pro 增量：新版 SmartVPN（Q7 上 404 由 setup 预检跳过）
    Q7SwitchDescription(key="smartvpn", name="SmartVPN", icon="mdi:vpn"),
]


class Q7Switch(CoordinatorEntity[Q7EnhanceCoordinator], SwitchEntity):
    entity_description: Q7SwitchDescription

    def __init__(self, coordinator: Q7EnhanceCoordinator, entry: ConfigEntry, description: Q7SwitchDescription, main_coordinator: Any) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = f"{DOMAIN}_q7_{_device_serial(main_coordinator)}_switch_{description.key}".lower()
        self._attr_device_info = _device_info(main_coordinator)

    @property
    def available(self) -> bool:
        # 开关端点已并入协调器轮询，端点数据缺失说明固件不支持
        return self.coordinator.last_update_success and self.coordinator.value(self.entity_description.key) is not None

    @property
    def is_on(self) -> bool | None:
        # 状态从协调器轮询数据读取（可写端点已并入 Q7_READ_ENDPOINTS），
        # 路由器侧（App/自动化）的状态变化会随刷新自动跟随
        data = self.coordinator.value(self.entity_description.key)
        if not isinstance(data, dict):
            return None
        return _to_bool(data.get("Enable"))

    @property
    def extra_state_attributes(self) -> dict | None:
        if self.entity_description.key == "wlanpowertimeswitch":
            data = self.coordinator.value("wlanpowertimeswitch")
            if isinstance(data, dict):
                return {
                    "PowerMode": data.get("PowerMode"),
                    "ScheduleState": data.get("ScheduleState"),
                    "Datelist": data.get("Datelist"),
                }
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.set_flag(self.entity_description.key, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.set_flag(self.entity_description.key, False)


async def async_setup_q7_switches(
    hass: HomeAssistant,
    entry: ConfigEntry,
    main_coordinator: Any,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = await _get_or_create_q7_coordinator(hass, entry, main_coordinator)
    entities: list[Q7Switch] = []
    for desc in Q7_SWITCHES:
        # 写之前先读一次，404（固件不支持）则不建实体
        try:
            resp = await coordinator.api.get_endpoint_config(Q7_WRITE_ENDPOINTS[desc.key])
            if resp.get("status") != 200 or not isinstance(resp.get("data"), dict):
                continue
        except Exception:  # noqa: BLE001
            continue
        entities.append(Q7Switch(coordinator, entry, desc, main_coordinator))
    async_add_entities(entities, update_before_add=False)


# ---------------------------------------------------------------------------
#   共享协调器管理
# ---------------------------------------------------------------------------
async def _get_or_create_q7_coordinator(
    hass: HomeAssistant, entry: ConfigEntry, main_coordinator: Any
) -> Q7EnhanceCoordinator:
    entry_data = hass.data.setdefault(DOMAIN, {}).setdefault(entry.entry_id, {})
    coordinator: Q7EnhanceCoordinator | None = entry_data.get(Q7_DOMAIN_KEY)
    if coordinator is None:
        api: HuaweiApi = main_coordinator.primary_router_api
        interval = int(main_coordinator._integration_options.update_interval)
        coordinator = Q7EnhanceCoordinator(hass, entry, api, interval)
        entry_data[Q7_DOMAIN_KEY] = coordinator
        # entry reload/卸载时自动停止轮询，避免旧实例残留与新实例双打路由器
        entry.async_on_unload(coordinator.async_shutdown)
        await coordinator.async_config_entry_first_refresh()
    return coordinator
