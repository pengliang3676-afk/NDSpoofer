# NDSpoofer 9.19-01（百度网盘设备指纹伪装）

两个产物：

- **NDSpoofer_9.19-01.dylib（卐解）**：TrollFools 注入百度网盘（com.baidu.netdisk）。
- **NDSpooferCraneManager_9.19-01_RootHide.deb（网盘解/卍解）**：RootHide 管理器，为每个 Crane 容器写入独立配置。

## 工作流程

1. TrollFools 把 dylib 注入百度网盘。
2. Sileo 安装网盘解 deb，桌面出现「网盘解」。
3. 打开网盘解，勾选容器，点「一键随机网盘身份」。每个容器独立抽一套：
   - 机型：iPhone 8（iPhone10,1 / D20AP / 2GB）或 iPhone SE3（iPhone14,6 / D49AP / 4GB）
   - 两机均为 375×667 @2x / 750×1334，与真机 SE2 完全同屏，UIScreen 不 hook，不存在机型/屏幕矛盾。
   - 系统版本：在该机型支持范围内随机（iPhone 8 到 16.x，SE3 到 18.x），build 与版本严格对应。
   - 磁盘 64/128/256GB（按机型 SKU）、设备名、独立 IDFV。
4. **彻底杀掉网盘进程后重新打开**，点悬浮「网盘伪装」按钮可自检当前读到的真实值/伪装值。

## 伪装出口（均有 NDProbe2 探针证据）

- C 层：sysctl/sysctlbyname（hw.machine、hw.model、hw.memsize、kern.osversion、kern.osproductversion、kern.hostname、machdep.cpu.brand_string）、uname、statfs（仅数据卷总量）。
- UIDevice：systemVersion、model、localizedModel、name、platform、bdc_platformString、bba_cachedSystemVersion、identifierForVendor。
- SAPIDeviceInfoHelper：deviceModel/deviceName/deviceType、plainDeviceInfoWithInterface:、retrieveDeviceInfoForKeys:、generateDeviceInfoWithPlainString:（明文串按 token 精确替换机型/系统/内存/磁盘）。
- BDPUserAgent：useagent_getDeviceInfo、composeUserAgentParameterWithOrigin:shouldEncodeURI:。
- 四种 UA 只改机型和系统版本；Mobile/15E148 永不触碰。
- 首启前预置 PASS_CUSTOM_SYS_VER / PASS_CUSTOM_UA_WK（passport SDK 登录页自定义 UA，免 Hook）。

## 明确不碰

- App 版本（13.33.5.x）、Sapi SDK 版本（9.8.12.20，网盘升级后需同步更新 passSdkVersion）、tpl=netdisk。
- cuid/utdid/deviceID/BDPanDeviceID 等业务 ID（Crane 已按容器隔离，钥匙串探针已证实）。
- TeamID、运营商、IP、定位、WebKit UA、任何 JS / WKWebView 页面环境。
- UIScreen（同屏机型无需改）。

## 恢复

网盘解里点「恢复安全」即关闭全部伪装（dylib 完全透传）；卸载 dylib 需 TrollFools 移除。
