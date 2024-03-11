/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */


#ifndef COMMON_CONFIG_H
#define COMMON_CONFIG_H

#include <functional>
#include "Util/mini.h"
#include "Util/onceToken.h"
#include "Util/NoticeCenter.h"
#include "macros.h"

using namespace std;
using namespace toolkit;

namespace mediakit {

//加载配置文件，如果配置文件不存在，那么会导出默认配置并生成配置文件
//加载配置文件成功后会触发kBroadcastUpdateConfig广播
//如果指定的文件名(ini_path)为空，那么会加载默认配置文件
//默认配置文件名为 /path/to/your/exe.ini
//加载配置文件成功后返回true，否则返回false
bool loadIniConfig(const char *ini_path = nullptr);

////////////广播名称///////////
namespace Broadcast {

//注册或反注册MediaSource事件广播
extern const string kBroadcastMediaChanged;
#define BroadcastMediaChangedArgs const bool &bRegist, MediaSource &sender

//录制mp4文件成功后广播
extern const string kBroadcastRecordMP4;
#define BroadcastRecordMP4Args const RecordInfo &info

// 录制 ts 文件后广播
extern const string kBroadcastRecordTs;
#define BroadcastRecordTsArgs const RecordInfo &info

//收到http api请求广播
extern const string kBroadcastHttpRequest;
#define BroadcastHttpRequestArgs const Parser &parser,const HttpSession::HttpResponseInvoker &invoker,bool &consumed,SockInfo &sender

//在http文件服务器中,收到http访问文件或目录的广播,通过该事件控制访问http目录的权限
extern const string kBroadcastHttpAccess;
#define BroadcastHttpAccessArgs const Parser &parser,const string &path,const bool &is_dir,const HttpSession::HttpAccessPathInvoker &invoker,SockInfo &sender

//在http文件服务器中,收到http访问文件或目录前的广播,通过该事件可以控制http url到文件路径的映射
//在该事件中通过自行覆盖path参数，可以做到譬如根据虚拟主机或者app选择不同http根目录的目的
extern const string kBroadcastHttpBeforeAccess;
#define BroadcastHttpBeforeAccessArgs const Parser &parser,string &path,SockInfo &sender

//该流是否需要认证？是的话调用invoker并传入realm,否则传入空的realm.如果该事件不监听则不认证
extern const string kBroadcastOnGetRtspRealm;
#define BroadcastOnGetRtspRealmArgs const MediaInfo &args,const RtspSession::onGetRealm &invoker,SockInfo &sender

//请求认证用户密码事件，user_name为用户名，must_no_encrypt如果为true，则必须提供明文密码(因为此时是base64认证方式),否则会导致认证失败
//获取到密码后请调用invoker并输入对应类型的密码和密码类型，invoker执行时会匹配密码
extern const string kBroadcastOnRtspAuth;
#define BroadcastOnRtspAuthArgs const MediaInfo &args,const string &realm,const string &user_name,const bool &must_no_encrypt,const RtspSession::onAuth &invoker,SockInfo &sender

//推流鉴权结果回调对象
//如果errMessage为空则代表鉴权成功
//enableHls: 是否允许转换hls
//enableMP4: 是否运行MP4录制
typedef std::function<void(const string &errMessage, bool enableHls, bool enableMP4)> PublishAuthInvoker;

//收到rtsp/rtmp推流事件广播，通过该事件控制推流鉴权
extern const string kBroadcastMediaPublish;
#define BroadcastMediaPublishArgs const MediaInfo &args,const Broadcast::PublishAuthInvoker &invoker,SockInfo &sender

//播放鉴权结果回调对象
//如果errMessage为空则代表鉴权成功
typedef std::function<void(const string &errMessage)> AuthInvoker;

//播放rtsp/rtmp/http-flv事件广播，通过该事件控制播放鉴权
extern const string kBroadcastMediaPlayed;
#define BroadcastMediaPlayedArgs const MediaInfo &args,const Broadcast::AuthInvoker &invoker,SockInfo &sender

//shell登录鉴权
extern const string kBroadcastShellLogin;
#define BroadcastShellLoginArgs const string &user_name,const string &passwd,const Broadcast::AuthInvoker &invoker,SockInfo &sender

//停止rtsp/rtmp/http-flv会话后流量汇报事件广播
extern const string kBroadcastFlowReport;
#define BroadcastFlowReportArgs const MediaInfo &args,const uint64_t &totalBytes,const uint64_t &totalDuration,const bool &isPlayer, SockInfo &sender

//未找到流后会广播该事件，请在监听该事件后去拉流或其他方式产生流，这样就能按需拉流了
extern const string kBroadcastNotFoundStream;
#define BroadcastNotFoundStreamArgs const MediaInfo &args,SockInfo &sender, const function<void()> &closePlayer

//某个流无人消费时触发，目的为了实现无人观看时主动断开拉流等业务逻辑
extern const string kBroadcastStreamNoneReader;
#define BroadcastStreamNoneReaderArgs MediaSource &sender

//更新配置文件事件广播,执行loadIniConfig函数加载配置文件成功后会触发该广播
extern const string kBroadcastReloadConfig;
#define BroadcastReloadConfigArgs void

#define ReloadConfigTag  ((void *)(0xFF))
#define RELOAD_KEY(arg,key)                              \
    do {                                                 \
        decltype(arg) arg##_tmp = mINI::Instance()[key]; \
        if (arg == arg##_tmp) {                          \
            return;                                      \
        }                                                \
        arg = arg##_tmp;                                 \
        InfoL << "reload config:" << key << "=" <<  arg; \
    } while(0)

//监听某个配置发送变更
#define LISTEN_RELOAD_KEY(arg, key, ...)                                          \
    do {                                                                          \
        static onceToken s_token_listen([](){                                     \
            NoticeCenter::Instance().addListener(ReloadConfigTag,                 \
                Broadcast::kBroadcastReloadConfig,[](BroadcastReloadConfigArgs) { \
                __VA_ARGS__;                                                      \
            });                                                                   \
        });                                                                       \
    } while(0)

#define GET_CONFIG(type, arg, key)           \
    static type arg = mINI::Instance()[key]; \
    LISTEN_RELOAD_KEY(arg, key, {            \
        RELOAD_KEY(arg, key);                \
    });

#define GET_CONFIG_FUNC(type, arg, key, ...)               \
    static type arg;                                       \
    do {                                                   \
        static onceToken s_token_set([](){                 \
            static auto lam = __VA_ARGS__ ;                \
            static auto arg##_str = mINI::Instance()[key]; \
            arg = lam(arg##_str);                          \
            LISTEN_RELOAD_KEY(arg, key, {                  \
                RELOAD_KEY(arg##_str, key);                \
                arg = lam(arg##_str);                      \
            });                                            \
        });                                                \
    } while(0)

} //namespace Broadcast

////////////通用配置///////////
namespace General{
//每个流媒体服务器的ID（GUID）
extern const string kMediaServerId;
//流量汇报事件流量阈值,单位KB，默认1MB
extern const string kFlowThreshold;
//流无人观看并且超过若干时间后才触发kBroadcastStreamNoneReader事件
//默认连续5秒无人观看然后触发kBroadcastStreamNoneReader事件
extern const string kStreamNoneReaderDelayMS;
//等待流注册超时时间，收到播放器后请求后，如果未找到相关流，服务器会等待一定时间，
//如果在这个时间内，相关流注册上了，那么服务器会立即响应播放器播放成功，
//否则会最多等待kMaxStreamWaitTimeMS毫秒，然后响应播放器播放失败
extern const string kMaxStreamWaitTimeMS;
//是否启动虚拟主机
extern const string kEnableVhost;
//拉流代理时是否添加静音音频
extern const string kAddMuteAudio;
//拉流代理时如果断流再重连成功是否删除前一次的媒体流数据，如果删除将重新开始，
//如果不删除将会接着上一次的数据继续写(录制hls/mp4时会继续在前一个文件后面写)
extern const string kResetWhenRePlay;
//是否默认推流时转换成hls，hook接口(on_publish)中可以覆盖该设置
extern const string kPublishToHls ;
//是否默认推流时mp4录像，hook接口(on_publish)中可以覆盖该设置
extern const string kPublishToMP4 ;
//合并写缓存大小(单位毫秒)，合并写指服务器缓存一定的数据后才会一次性写入socket，这样能提高性能，但是会提高延时
//开启后会同时关闭TCP_NODELAY并开启MSG_MORE
extern const string kMergeWriteMS ;
//全局的时间戳覆盖开关，在转协议时，对frame进行时间戳覆盖
extern const string kModifyStamp;
//按需转协议的开关
extern const string kHlsDemand;
extern const string kRtspDemand;
extern const string kRtmpDemand;
extern const string kTSDemand;
extern const string kFMP4Demand;
//转协议是否全局开启或忽略音频
extern const string kEnableAudio;
//最多等待未初始化的Track 10秒，超时之后会忽略未初始化的Track
extern const string kWaitTrackReadyMS;
//如果直播流只有单Track，最多等待3秒，超时后未收到其他Track的数据，则认为是单Track
//如果协议元数据有声明特定track数，那么无此等待时间
extern const string kWaitAddTrackMS;
//如果track未就绪，我们先缓存帧数据，但是有最大个数限制(100帧时大约4秒)，防止内存溢出
extern const string kUnreadyFrameCache;
//推流断开后可以在超时时间内重新连接上继续推流，这样播放器会接着播放。
//置0关闭此特性(推流断开会导致立即断开播放器)
extern const string kContinuePushMS;
//本机客户端可见ip，作为服务器时一般为公网ip，置空时，会自动获取网卡ip
extern const string kExternIP;
//指定绑定特定网卡IP地址，适用于非法内网IP,Linux系统,例如：eth0，优先级低于externIP
extern const string kEthName;
//通知配置文件调整日志输出根目录
extern const string kLogRootPath;

}//namespace General


////////////HTTP配置///////////
namespace Http {
//http 文件发送缓存大小
extern const string kSendBufSize;
//http 最大请求字节数
extern const string kMaxReqSize;
//http keep-alive秒数
extern const string kKeepAliveSecond;
//http 字符编码
extern const string kCharSet;
//http 服务器根目录
extern const string kRootPath;
//http 服务器虚拟目录 虚拟目录名和文件路径使用","隔开，多个配置路径间用";"隔开，例如  path_d,d:/record;path_e,e:/record
extern const string kVirtualPath;
//http 404错误提示内容
extern const string kNotFound;
//是否显示文件夹菜单
extern const string kDirMenu;

extern const string kPort;
extern const string kSSLPort;
}//namespace Http

////////////SHELL配置///////////
namespace Shell {
extern const string kMaxReqSize;
extern const string kPort;
} //namespace Shell

////////////组播配置///////////
namespace MultiCast {
//组播分配起始地址
extern const string kAddrMin;
//组播分配截止地址
extern const string kAddrMax;
//组播TTL
extern const string kUdpTTL;
} //namespace MultiCast

/**
 * mysql数据库相关设置名
 */
namespace Mysql {
//ip
extern const string kIp;
//端口号
extern const string kPort;
//登录用户名
extern const string kUser;
//登录密码
extern const string kPassword;
}
}  // namespace mediakit

#endif /* COMMON_CONFIG_H */
