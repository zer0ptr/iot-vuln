# IoT Vulnerability Analysis 

> A personal collection of vulnerability reproduction and analysis reports in the IoT/embedded systems domain.

---

## 📋 Reports
> Updating...

| Vulnerability | Device/Component | Type | Report |
|--------|------------------|------|--------|
| CNVD-2013-11625 | DIR-815 | Stack Overflow | [📄 Link](./DIR-815路由器多次溢出漏洞分析复现/README_en.md) |
| CVE-2018-7034 | D-Link / TEW-751DR | Information Leakage | [📄 Link](./D-Link-CVE-2018-7034登录信息泄露漏洞复现/README.md) |
| SSV-97887 | TP-Link SR20 | OS Command Injection | [📄 Link](./TP-Link-SR20路由器命令执行漏洞分析复现/README.md) |
| CVE-2017-17215 | HUAWEI HG-532 | RCE | [📄 Link](./华为HG532路由器远程代码执行漏洞分析复现/iot-huawei-hg532-rce.md)

---

## 🔧 Tools & Environment

- **OS**: Ubuntu 22.04 LTS / Ubuntu 16.04
- **Debugging**: GDB + pwndbg / GEF, QEMU (user/system mode)
- **Analysis**: Ghidra / IDA Pro, FirmAE, Binwalk

---

## 📝 Report Format

Each report generally covers:

- Vulnerability description and affected versions
- Root cause analysis with code references
- Trigger/exploitation conditions
- References

---

## 📬 Contact

- **Email**: [iszhenghailin@gmail.com](iszhenghailin@gmail.com)
- **Blog**: [Zer0ptr's Blog](https://blog.zer0ptr.icu/enblog/)