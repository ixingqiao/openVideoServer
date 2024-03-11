﻿/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <algorithm>
#include "Common/config.h"
#include "strCoding.h"
#include "HttpSession.h"
#include "HttpConst.h"
#include "Util/base64.h"
#include "Util/SHA1.h"
using namespace toolkit;

namespace mediakit {

HttpSession::HttpSession(const Socket::Ptr &pSock) : TcpSession(pSock) {
    TraceP(this);
    GET_CONFIG(uint32_t,keep_alive_sec,Http::kKeepAliveSecond);
    pSock->setSendTimeOutSecond(keep_alive_sec);
}

HttpSession::~HttpSession() {
    TraceP(this);
}

void HttpSession::Handle_Req_HEAD(ssize_t &content_len){
    //暂时全部返回200 OK，因为HTTP GET存在按需生成流的操作，所以不能按照HTTP GET的流程返回
    //如果直接返回404，那么又会导致按需生成流的逻辑失效，所以HTTP HEAD在静态文件或者已存在资源时才有效
    //对于按需生成流的直播场景并不适用
    sendResponse(200, false);
}

void HttpSession::Handle_Req_OPTIONS(ssize_t &content_len) {
    KeyValue header;
    header.emplace("Allow", "GET, POST, OPTIONS");
    header.emplace("Access-Control-Allow-Origin", "*");
    header.emplace("Access-Control-Allow-Credentials", "true");
    header.emplace("Access-Control-Request-Methods", "GET, POST, OPTIONS");
    header.emplace("Access-Control-Request-Headers", "Accept,Accept-Language,Content-Language,Content-Type");
    sendResponse(200, true, nullptr, header);
}

ssize_t HttpSession::onRecvHeader(const char *header,size_t len) {
    typedef void (HttpSession::*HttpCMDHandle)(ssize_t &);
    static unordered_map<string, HttpCMDHandle> s_func_map;
    static onceToken token([]() {
        s_func_map.emplace("GET",&HttpSession::Handle_Req_GET);
        s_func_map.emplace("POST",&HttpSession::Handle_Req_POST);
        s_func_map.emplace("HEAD",&HttpSession::Handle_Req_HEAD);
        s_func_map.emplace("OPTIONS",&HttpSession::Handle_Req_OPTIONS);
    }, nullptr);

    _parser.Parse(header);
    CHECK(_parser.Url()[0] == '/');

    urlDecode(_parser);
    string cmd = _parser.Method();
    auto it = s_func_map.find(cmd);
    if (it == s_func_map.end()) {
        WarnP(this) << "不支持该命令:" << cmd;
        sendResponse(405, true);
        return 0;
    }

    //跨域
    _origin = _parser["Origin"];

    //默认后面数据不是content而是header
    ssize_t content_len = 0;
    (this->*(it->second))(content_len);

    //清空解析器节省内存
    _parser.Clear();
    //返回content长度
    return content_len;
}

void HttpSession::onRecvContent(const char *data,size_t len) {
    if(_contentCallBack){
        if(!_contentCallBack(data,len)){
            _contentCallBack = nullptr;
        }
    }
}

void HttpSession::onRecv(const Buffer::Ptr &pBuf) {
    _ticker.resetTime();
    input(pBuf->data(),pBuf->size());
}

void HttpSession::onError(const SockException& err) {
    //http客户端
    TraceP(this) << err.what();
}

void HttpSession::onManager() {
    GET_CONFIG(uint32_t,keepAliveSec,Http::kKeepAliveSecond);

    if(_ticker.elapsedTime() > keepAliveSec * 1000){
        //1分钟超时
        shutdown(SockException(Err_timeout,"session timeout"));
    }
}

bool HttpSession::checkWebSocket(){
    auto Sec_WebSocket_Key = _parser["Sec-WebSocket-Key"];
    if (Sec_WebSocket_Key.empty()) {
        return false;
    }
    auto Sec_WebSocket_Accept = encodeBase64(SHA1::encode_bin(Sec_WebSocket_Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));

    KeyValue headerOut;
    headerOut["Cache-Control"] = "no-store";
    headerOut["Upgrade"] = "websocket";
    headerOut["Connection"] = "Upgrade";
    headerOut["Sec-WebSocket-Accept"] = Sec_WebSocket_Accept;
    if (!_parser["Sec-WebSocket-Protocol"].empty()) {
        headerOut["Sec-WebSocket-Protocol"] = _parser["Sec-WebSocket-Protocol"];
    }

    auto res_cb = [this, headerOut]() {
        _live_over_websocket = true;
        sendResponse(101, false, nullptr, headerOut, nullptr, true);
    };

    //这是普通的websocket连接
    if (!onWebSocketConnect(_parser)) {
        sendResponse(501, true, nullptr, headerOut);
        return true;
    }
    sendResponse(101, false, nullptr, headerOut, nullptr, true);
    return true;
}

void HttpSession::Handle_Req_GET(ssize_t &content_len) {
    Handle_Req_GET_l(content_len, true);
}

void HttpSession::Handle_Req_GET_l(ssize_t &content_len, bool sendBody) {
    //先看看是否为WebSocket请求
    if (checkWebSocket()) {
        content_len = -1;
        _contentCallBack = [this](const char *data, size_t len) {
            WebSocketSplitter::decode((uint8_t *) data, len);
            //_contentCallBack是可持续的，后面还要处理后续数据
            return true;
        };
        return;
    }

    if (emitHttpEvent(false)) {
        //拦截http api事件
        return;
    }

    bool bClose = !strcasecmp(_parser["Connection"].data(),"close");
    weak_ptr<HttpSession> weakSelf = dynamic_pointer_cast<HttpSession>(shared_from_this());
}

static string dateStr() {
    char buf[64];
    time_t tt = time(NULL);
    strftime(buf, sizeof buf, "%a, %b %d %Y %H:%M:%S GMT", gmtime(&tt));
    return buf;
}

class AsyncSenderData {
public:
    friend class AsyncSender;
    typedef std::shared_ptr<AsyncSenderData> Ptr;
    AsyncSenderData(const TcpSession::Ptr &session, const HttpBody::Ptr &body, bool close_when_complete) {
        _session = dynamic_pointer_cast<HttpSession>(session);
        _body = body;
        _close_when_complete = close_when_complete;
    }
    ~AsyncSenderData() = default;
private:
    std::weak_ptr<HttpSession> _session;
    HttpBody::Ptr _body;
    bool _close_when_complete;
    bool _read_complete = false;
};

class AsyncSender {
public:
    typedef std::shared_ptr<AsyncSender> Ptr;
    static bool onSocketFlushed(const AsyncSenderData::Ptr &data) {
        if (data->_read_complete) {
            if (data->_close_when_complete) {
                //发送完毕需要关闭socket
                shutdown(data->_session.lock());
            }
            return false;
        }

        GET_CONFIG(uint32_t, sendBufSize, Http::kSendBufSize);
        data->_body->readDataAsync(sendBufSize, [data](const Buffer::Ptr &sendBuf) {
            auto session = data->_session.lock();
            if (!session) {
                //本对象已经销毁
                return;
            }
            session->async([data, sendBuf]() {
                auto session = data->_session.lock();
                if (!session) {
                    //本对象已经销毁
                    return;
                }
                onRequestData(data, session, sendBuf);
            }, false);
        });
        return true;
    }

private:
    static void onRequestData(const AsyncSenderData::Ptr &data, const std::shared_ptr<HttpSession> &session, const Buffer::Ptr &sendBuf) {
        session->_ticker.resetTime();
        if (sendBuf && session->send(sendBuf) != -1) {
            //文件还未读完，还需要继续发送
            if (!session->isSocketBusy()) {
                //socket还可写，继续请求数据
                onSocketFlushed(data);
            }
            return;
        }
        //文件写完了
        data->_read_complete = true;
        if (!session->isSocketBusy() && data->_close_when_complete) {
            shutdown(session);
        }
    }

    static void shutdown(const std::shared_ptr<HttpSession> &session) {
        if(session){
            session->shutdown(SockException(Err_shutdown, StrPrinter << "close connection after send http body completed."));
        }
    }
};

static const string kDate = "Date";
static const string kServer = "Server";
static const string kConnection = "Connection";
static const string kKeepAlive = "Keep-Alive";
static const string kContentType = "Content-Type";
static const string kContentLength = "Content-Length";
static const string kAccessControlAllowOrigin = "Access-Control-Allow-Origin";
static const string kAccessControlAllowCredentials = "Access-Control-Allow-Credentials";

void HttpSession::sendResponse(int code,
                               bool bClose,
                               const char *pcContentType,
                               const HttpSession::KeyValue &header,
                               const HttpBody::Ptr &body,
                               bool no_content_length ){
    GET_CONFIG(string,charSet,Http::kCharSet);
    GET_CONFIG(uint32_t,keepAliveSec,Http::kKeepAliveSecond);

    //body默认为空
    ssize_t size = 0;
    if (body && body->remainSize()) {
        //有body，获取body大小
        size = body->remainSize();
    }

    if(no_content_length){
        //http-flv直播是Keep-Alive类型
        bClose = false;
    }else if((size_t) size >= SIZE_MAX || size < 0 ){
        //不固定长度的body，那么发送完body后应该关闭socket，以便浏览器做下载完毕的判断
        bClose = true;
    }

    HttpSession::KeyValue &headerOut = const_cast<HttpSession::KeyValue &>(header);
    headerOut.emplace(kDate, dateStr());
    headerOut.emplace(kServer, kServerName);
    headerOut.emplace(kConnection, bClose ? "close" : "keep-alive");
    if(!bClose){
        string keepAliveString = "timeout=";
        keepAliveString += to_string(keepAliveSec);
        keepAliveString += ", max=100";
        headerOut.emplace(kKeepAlive,std::move(keepAliveString));
    }

    if(!_origin.empty()){
        //设置跨域
        headerOut.emplace(kAccessControlAllowOrigin,_origin);
        headerOut.emplace(kAccessControlAllowCredentials, "true");
    }

    if(!no_content_length && size >= 0 && (size_t)size < SIZE_MAX){
        //文件长度为固定值,且不是http-flv强制设置Content-Length
        headerOut[kContentLength] = to_string(size);
    }

    if(size && !pcContentType){
        //有body时，设置缺省类型
        pcContentType = "text/plain";
    }

    if((size || no_content_length) && pcContentType){
        //有body时，设置文件类型
        string strContentType = pcContentType;
        strContentType += "; charset=";
        strContentType += charSet;
        headerOut.emplace(kContentType,std::move(strContentType));
    }

    //发送http头
    string str;
    str.reserve(256);
    str += "HTTP/1.1 " ;
    str += to_string(code);
    str += ' ';
    str += getHttpStatusMessage(code) ;
    str += "\r\n";
    for (auto &pr : header) {
        str += pr.first ;
        str += ": ";
        str += pr.second;
        str += "\r\n";
    }
    str += "\r\n";
    SockSender::send(std::move(str));
    _ticker.resetTime();

    if(!size){
        //没有body
        if(bClose){
            shutdown(SockException(Err_shutdown,StrPrinter << "close connection after send http header completed with status code:" << code));
        }
        return;
    }

    GET_CONFIG(uint32_t, sendBufSize, Http::kSendBufSize);
    if(body->remainSize() > sendBufSize){
        //文件下载提升发送性能
        setSocketFlags();
    }

    //发送http body
    AsyncSenderData::Ptr data = std::make_shared<AsyncSenderData>(shared_from_this(),body,bClose);
    getSock()->setOnFlush([data](){
        return AsyncSender::onSocketFlushed(data);
    });
    AsyncSender::onSocketFlushed(data);
}

string HttpSession::urlDecode(const string &str){
    auto ret = strCoding::UrlDecode(str);
#ifdef _WIN32
    GET_CONFIG(string,charSet,Http::kCharSet);
    bool isGb2312 = !strcasecmp(charSet.data(), "gb2312");
    if (isGb2312) {
        ret = strCoding::UTF8ToGB2312(ret);
    }
#endif // _WIN32
    return ret;
}

void HttpSession::urlDecode(Parser &parser){
    parser.setUrl(urlDecode(parser.Url()));
    for(auto &pr : _parser.getUrlArgs()){
        const_cast<string &>(pr.second) = urlDecode(pr.second);
    }
}

bool HttpSession::emitHttpEvent(bool doInvoke){
    bool bClose = !strcasecmp(_parser["Connection"].data(),"close");
    /////////////////////异步回复Invoker///////////////////////////////
    weak_ptr<HttpSession> weakSelf = dynamic_pointer_cast<HttpSession>(shared_from_this());
    HttpResponseInvoker invoker = [weakSelf,bClose](int code, const KeyValue &headerOut, const HttpBody::Ptr &body){
        auto strongSelf = weakSelf.lock();
        if(!strongSelf) {
            return;
        }
        strongSelf->async([weakSelf, bClose, code, headerOut, body]() {
            auto strongSelf = weakSelf.lock();
            if (!strongSelf) {
                //本对象已经销毁
                return;
            }
            strongSelf->sendResponse(code, bClose, nullptr, headerOut, body);
        });
    };
    ///////////////////广播HTTP事件///////////////////////////
    bool consumed = false;//该事件是否被消费
    NoticeCenter::Instance().emitEvent(Broadcast::kBroadcastHttpRequest,_parser,invoker,consumed,static_cast<SockInfo &>(*this));
    if(!consumed && doInvoke){
        //该事件无人消费，所以返回404
        invoker(404,KeyValue(), HttpBody::Ptr());
    }
    return consumed;
}

void HttpSession::Handle_Req_POST(ssize_t &content_len) {
    GET_CONFIG(size_t,maxReqSize,Http::kMaxReqSize);

    ssize_t totalContentLen = _parser["Content-Length"].empty() ? -1 : atoll(_parser["Content-Length"].data());

    if(totalContentLen == 0){
        //content为空
        //emitHttpEvent内部会选择是否关闭连接
        emitHttpEvent(true);
        return;
    }

    if(totalContentLen > 0 && (size_t)totalContentLen < maxReqSize ){
        //返回固定长度的content
        content_len = totalContentLen;
        auto parserCopy = _parser;
        _contentCallBack = [this,parserCopy](const char *data,size_t len){
            //恢复http头
            _parser = parserCopy;
            //设置content
            _parser.setContent(string(data,len));
            //触发http事件，emitHttpEvent内部会选择是否关闭连接
            emitHttpEvent(true);
            //清空数据,节省内存
            _parser.Clear();
            //content已经接收完毕
            return false;
        };
    }else{
        //返回不固定长度的content或者超过长度限制的content
        content_len = -1;
        auto parserCopy = _parser;
        std::shared_ptr<size_t> recvedContentLen = std::make_shared<size_t>(0);
        bool bClose = !strcasecmp(_parser["Connection"].data(),"close");

        _contentCallBack = [this,parserCopy,totalContentLen,recvedContentLen,bClose](const char *data,size_t len){
            *(recvedContentLen) += len;
            if (totalContentLen < 0) {
                //不固定长度的content,源源不断接收数据
                onRecvUnlimitedContent(parserCopy, data, len, SIZE_MAX, *(recvedContentLen));
                return true;
            }

            //长度超过限制的content
            onRecvUnlimitedContent(parserCopy,data,len,totalContentLen,*(recvedContentLen));

            if(*(recvedContentLen) < (size_t)totalContentLen){
                //数据还没接收完毕
                //_contentCallBack是可持续的，后面还要处理后续content数据
                return true;
            }

            //数据接收完毕
            if(!bClose){
                //keep-alive类型连接
                //content接收完毕，后续都是http header
                setContentLen(0);
                //content已经接收完毕
                return false;
            }

            //连接类型是close类型，收完content就关闭连接
            shutdown(SockException(Err_shutdown,"recv http content completed"));
            //content已经接收完毕
            return false ;
        };
    }
    //有后续content数据要处理,暂时不关闭连接
}

void HttpSession::sendNotFound(bool bClose) {
    GET_CONFIG(string,notFound,Http::kNotFound);
    sendResponse(404, bClose,"text/html",KeyValue(),std::make_shared<HttpStringBody>(notFound));
}

void HttpSession::setSocketFlags(){
    GET_CONFIG(int, mergeWriteMS, General::kMergeWriteMS);
    if(mergeWriteMS > 0) {
        //推流模式下，关闭TCP_NODELAY会增加推流端的延时，但是服务器性能将提高
        SockUtil::setNoDelay(getSock()->rawFD(), false);
        //播放模式下，开启MSG_MORE会增加延时，但是能提高发送性能
        setSendFlags(SOCKET_DEFAULE_FLAGS | FLAG_MORE);
    }
}

void HttpSession::onWebSocketEncodeData(Buffer::Ptr buffer){
    _total_bytes_usage += buffer->size();
    send(std::move(buffer));
}

void HttpSession::onWebSocketDecodeComplete(const WebSocketHeader &header_in){
    WebSocketHeader& header = const_cast<WebSocketHeader&>(header_in);
    header._mask_flag = false;

    switch (header._opcode) {
        case WebSocketHeader::CLOSE: {
            encode(header, nullptr);
            shutdown(SockException(Err_shutdown, "recv close request from client"));
            break;
        }

        default : break;
    }
}
} /* namespace mediakit */
