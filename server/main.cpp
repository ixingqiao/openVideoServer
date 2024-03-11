﻿/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#include <signal.h>
#include <iostream>
#include "Util/File.h"
#include "Util/logger.h"
#include "Util/SSLBox.h"
#include "Util/onceToken.h"
#include "Util/CMD.h"
#include "Network/TcpServer.h"
#include "Network/UdpServer.h"
#include "Poller/EventPoller.h"
#include "Common/config.h"
#include "Shell/ShellSession.h"
#include "Http/WebSocketSession.h"
#include "WebApi.h"
#include "WebHook.h"

#if defined(ENABLE_VERSION)
#include "Version.h"
#endif

#if !defined(_WIN32)
#include "System.h"
#endif//!defined(_WIN32)

using namespace std;
using namespace toolkit;
using namespace mediakit;

class CMD_main : public CMD {
public:
    CMD_main() {
        _parser.reset(new OptionParser(nullptr));

#if !defined(_WIN32)
        (*_parser) << Option('d',/*该选项简称，如果是\x00则说明无简称*/
                             "daemon",/*该选项全称,每个选项必须有全称；不得为null或空字符串*/
                             Option::ArgNone,/*该选项后面必须跟值*/
                             nullptr,/*该选项默认值*/
                             false,/*该选项是否必须赋值，如果没有默认值且为ArgRequired时用户必须提供该参数否则将抛异常*/
                             "是否以Daemon方式启动",/*该选项说明文字*/
                             nullptr);
#endif//!defined(_WIN32)

        (*_parser) << Option('l',/*该选项简称，如果是\x00则说明无简称*/
                             "level",/*该选项全称,每个选项必须有全称；不得为null或空字符串*/
                             Option::ArgRequired,/*该选项后面必须跟值*/
                             to_string(LTrace).data(),/*该选项默认值*/
                             false,/*该选项是否必须赋值，如果没有默认值且为ArgRequired时用户必须提供该参数否则将抛异常*/
                             "日志等级,LTrace~LError(0~4)",/*该选项说明文字*/
                             nullptr);

        (*_parser) << Option('m',/*该选项简称，如果是\x00则说明无简称*/
                             "max_day",/*该选项全称,每个选项必须有全称；不得为null或空字符串*/
                             Option::ArgRequired,/*该选项后面必须跟值*/
                             "7",/*该选项默认值*/
                             false,/*该选项是否必须赋值，如果没有默认值且为ArgRequired时用户必须提供该参数否则将抛异常*/
                             "日志最多保存天数",/*该选项说明文字*/
                             nullptr);

        (*_parser) << Option('c',/*该选项简称，如果是\x00则说明无简称*/
                             "config",/*该选项全称,每个选项必须有全称；不得为null或空字符串*/
                             Option::ArgRequired,/*该选项后面必须跟值*/
                             (exeDir() + "config.ini").data(),/*该选项默认值*/
                             false,/*该选项是否必须赋值，如果没有默认值且为ArgRequired时用户必须提供该参数否则将抛异常*/
                             "配置文件路径",/*该选项说明文字*/
                             nullptr);

        (*_parser) << Option('s',/*该选项简称，如果是\x00则说明无简称*/
                             "ssl",/*该选项全称,每个选项必须有全称；不得为null或空字符串*/
                             Option::ArgRequired,/*该选项后面必须跟值*/
                             (exeDir() + "default.pem").data(),/*该选项默认值*/
                             false,/*该选项是否必须赋值，如果没有默认值且为ArgRequired时用户必须提供该参数否则将抛异常*/
                             "ssl证书文件或文件夹,支持p12/pem类型",/*该选项说明文字*/
                             nullptr);

        (*_parser) << Option('t',/*该选项简称，如果是\x00则说明无简称*/
                             "threads",/*该选项全称,每个选项必须有全称；不得为null或空字符串*/
                             Option::ArgRequired,/*该选项后面必须跟值*/
                             to_string(thread::hardware_concurrency()).data(),/*该选项默认值*/
                             false,/*该选项是否必须赋值，如果没有默认值且为ArgRequired时用户必须提供该参数否则将抛异常*/
                             "启动事件触发线程数",/*该选项说明文字*/
                             nullptr);

#if defined(ENABLE_VERSION)
        (*_parser) << Option('v', "version", Option::ArgNone, nullptr, false, "显示版本号",
                             [](const std::shared_ptr<ostream> &stream, const string &arg) -> bool {
                                 //版本信息
                                 *stream << "编译日期: " << BUILD_TIME << std::endl;
                                 *stream << "当前git分支: " << BRANCH_NAME << std::endl;
                                 *stream << "当前git hash值: " << COMMIT_HASH << std::endl;
                                 throw ExitException();
                             });
#endif
    }

    ~CMD_main() override{}
    const char *description() const override{
        return "主程序命令参数";
    }
};

//全局变量，在WebApi中用于保存配置文件用
string g_ini_file;

int start_main(int argc,char *argv[]) {
    {
        CMD_main cmd_main;
        try {
            cmd_main.operator()(argc, argv);
        } catch (ExitException &) {
            return 0;
        } catch (std::exception &ex) {
            cout << ex.what() << endl;
            return -1;
        }

        bool bDaemon = cmd_main.hasKey("daemon");
        LogLevel logLevel = (LogLevel) cmd_main["level"].as<int>();
        logLevel = MIN(MAX(logLevel, LTrace), LError);
        g_ini_file = cmd_main["config"];
        string ssl_file = cmd_main["ssl"];
        int threads = cmd_main["threads"];

        //加载配置文件，如果配置文件不存在就创建一个
        loadIniConfig(g_ini_file.data());

        //设置日志
        Logger::Instance().add(std::make_shared<ConsoleChannel>("ConsoleChannel", logLevel));
#ifndef ANDROID
        std::string logPath = exeDir();
        GET_CONFIG(string, log_root_path, General::kLogRootPath);
        if (!log_root_path.empty() && File::is_dir(log_root_path.c_str())) {
            logPath = log_root_path;
        }
        auto fileChannel = std::make_shared<FileChannel>("FileChannel", logPath + "log/", logLevel);
        //日志最多保存天数
        fileChannel->setMaxDay(cmd_main["max_day"]);
        Logger::Instance().add(fileChannel);
#endif//

#if !defined(_WIN32)
        pid_t pid = getpid();
        if (bDaemon) {
            //启动守护进程
            System::startDaemon();
        }
        //开启崩溃捕获等
        System::systemSetup();
#endif//!defined(_WIN32)

        //启动异步日志线程
        Logger::Instance().setWriter(std::make_shared<AsyncLogWriter>());

        InfoL << "服务启动 OpenVideoServer start";
#if defined(ENABLE_VERSION)
        InfoL << "编译日期: " << BUILD_TIME;
        InfoL << "当前git分支: " << BRANCH_NAME;
        InfoL << "当前git hash值: " << COMMIT_HASH;
#endif
        if (!File::is_dir(ssl_file.data())) {
            //不是文件夹，加载证书，证书包含公钥和私钥
            SSL_Initor::Instance().loadCertificate(ssl_file.data());
        } else {
            //加载文件夹下的所有证书
            File::scanDir(ssl_file, [](const string &path, bool isDir) {
                if (!isDir) {
                    //最后的一个证书会当做默认证书(客户端ssl握手时未指定主机)
                    SSL_Initor::Instance().loadCertificate(path.data());
                }
                return true;
            });
        }
        uint16_t shellPort = mINI::Instance()[Shell::kPort];
        uint16_t httpPort = mINI::Instance()[Http::kPort];
        uint16_t httpsPort = mINI::Instance()[Http::kSSLPort];

        //设置poller线程数,该函数必须在使用ZLToolKit网络相关对象之前调用才能生效
        EventPollerPool::setPoolSize(threads);

        //简单的telnet服务器，可用于服务器调试，但是不能使用23端口，否则telnet上了莫名其妙的现象
        //测试方法:telnet 127.0.0.1 9000
        auto shellSrv = std::make_shared<TcpServer>();

        //http[s]服务器
        auto httpSrv = std::make_shared<TcpServer>();
        auto httpsSrv = std::make_shared<TcpServer>();

        try {
            //http服务器，端口默认80
            if (httpPort) { httpSrv->start<HttpSession>(httpPort); }
            //https服务器，端口默认443
            if (httpsPort) { httpsSrv->start<HttpsSession>(httpsPort); }

            //telnet远程调试服务器
            if (shellPort) { shellSrv->start<ShellSession>(shellPort); }

#if defined(ENABLE_RTPPROXY)
            //创建rtp服务器
            if (rtpPort) { rtpServer->start(rtpPort); }
#endif//defined(ENABLE_RTPPROXY)

#if defined(ENABLE_WEBRTC)
            //webrtc udp服务器
            if (rtcPort) { rtcSrv->start<WebRtcSession>(rtcPort); }
#endif//defined(ENABLE_WEBRTC)

        } catch (std::exception &ex) {
            WarnL << "端口占用或无权限:" << ex.what() << endl;
            ErrorL << "程序启动失败，请修改配置文件中端口号后重试!" << endl;
            sleep(1);
#if !defined(_WIN32)
            if (pid != getpid()) {
                kill(pid, SIGINT);
            }
#endif
            return -1;
        }

        installWebApi();
        InfoL << "已启动http api 接口";
        installWebHook();
        InfoL << "已启动http hook 接口";

        //设置退出信号处理函数
        static bool exit_flag = false;
        signal(SIGINT, [](int) {
            InfoL << "SIGINT:exit";
            signal(SIGINT, SIG_IGN);// 设置退出信号
            //sem.post();
            exit_flag = true;
        });// 设置退出信号

#if !defined(_WIN32)
        signal(SIGHUP, [](int) { mediakit::loadIniConfig(g_ini_file.data()); });
#endif
        // 兼容校时发生的系统时间回退的方案
        uint64_t t1 = time(nullptr), t2 = time(nullptr);
        while (!exit_flag) {
            sleep(10); 
            t2 = time(nullptr);
            if (t2 < t1) {
                ErrorL << "时间回退，进程重启t1：" << t1 << " t2: " << t2;
                break;
            }
            t1 = t2;
        }
    }
    unInstallWebApi();
    unInstallWebHook();
    //休眠1秒再退出，防止资源释放顺序错误
    InfoL << "程序退出中,请等待...";
    sleep(1);
    InfoL << "程序退出完毕!";
    return 0;
}

#ifndef DISABLE_MAIN
int main(int argc,char *argv[]) {
    return start_main(argc,argv);
}
#endif //DISABLE_MAIN


