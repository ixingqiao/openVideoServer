﻿/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#ifndef ZLMEDIAKIT_WEBSOCKETSESSION_H
#define ZLMEDIAKIT_WEBSOCKETSESSION_H

#include "HttpSession.h"
#include "Network/TcpServer.h"

/**
 * 数据发送拦截器
 */
class SendInterceptor{
public:
    typedef function<ssize_t (const Buffer::Ptr &buf)> onBeforeSendCB;
    SendInterceptor() = default;
    virtual ~SendInterceptor() = default;
    virtual void setOnBeforeSendCB(const onBeforeSendCB &cb) = 0;
};

/**
 * 该类实现了TcpSession派生类发送数据的截取
 * 目的是发送业务数据前进行websocket协议的打包
 */
template <typename TcpSessionType>
class TcpSessionTypeImp : public TcpSessionType, public SendInterceptor{
public:
    typedef std::shared_ptr<TcpSessionTypeImp> Ptr;

    TcpSessionTypeImp(const Parser &header, const HttpSession &parent, const Socket::Ptr &pSock) :
            TcpSessionType(pSock), _identifier(parent.getIdentifier()) {}

    ~TcpSessionTypeImp() {}

    /**
     * 设置发送数据截取回调函数
     * @param cb 截取回调函数
     */
    void setOnBeforeSendCB(const onBeforeSendCB &cb) override {
        _beforeSendCB = cb;
    }

protected:
    /**
     * 重载send函数截取数据
     * @param buf 需要截取的数据
     * @return 数据字节数
     */
    ssize_t send(Buffer::Ptr buf) override {
        if (_beforeSendCB) {
            return _beforeSendCB(buf);
        }
        return TcpSessionType::send(std::move(buf));
    }

    string getIdentifier() const override {
        return _identifier;
    }

private:
    string _identifier;
    onBeforeSendCB _beforeSendCB;
};

template <typename TcpSessionType>
class TcpSessionCreator {
public:
    //返回的TcpSession必须派生于SendInterceptor，可以返回null
    TcpSession::Ptr operator()(const Parser &header, const HttpSession &parent, const Socket::Ptr &pSock){
        return std::make_shared<TcpSessionTypeImp<TcpSessionType> >(header,parent,pSock);
    }
};

/**
* 通过该模板类可以透明化WebSocket协议，
* 用户只要实现WebSock协议下的具体业务协议，譬如基于WebSocket协议的Rtmp协议等
*/
template<typename Creator, typename HttpSessionType = HttpSession, WebSocketHeader::Type DataType = WebSocketHeader::TEXT>
class WebSocketSessionBase : public HttpSessionType {
public:
    WebSocketSessionBase(const Socket::Ptr &pSock) : HttpSessionType(pSock){}
    virtual ~WebSocketSessionBase(){}

    //收到eof或其他导致脱离TcpServer事件的回调
    void onError(const SockException &err) override{
        HttpSessionType::onError(err);
        if(_session){
            _session->onError(err);
        }
    }
    //每隔一段时间触发，用来做超时管理
    void onManager() override{
        if(_session){
            _session->onManager();
        }else{
            HttpSessionType::onManager();
        }
    }

    void attachServer(const Server &server) override{
        HttpSessionType::attachServer(server);
        _weak_server = const_cast<Server &>(server).shared_from_this();
    }

protected:
    /**
     * websocket客户端连接上事件
     * @param header http头
     * @return true代表允许websocket连接，否则拒绝
     */
    bool onWebSocketConnect(const Parser &header) override{
        //创建websocket session类
        _session = _creator(header, *this,HttpSessionType::getSock());
        if(!_session){
            //此url不允许创建websocket连接
            return false;
        }
        auto strongServer = _weak_server.lock();
        if(strongServer){
            _session->attachServer(*strongServer);
        }

        //此处截取数据并进行websocket协议打包
        weak_ptr<WebSocketSessionBase> weakSelf = dynamic_pointer_cast<WebSocketSessionBase>(HttpSessionType::shared_from_this());
        dynamic_pointer_cast<SendInterceptor>(_session)->setOnBeforeSendCB([weakSelf](const Buffer::Ptr &buf) {
            auto strongSelf = weakSelf.lock();
            if (strongSelf) {
                WebSocketHeader header;
                header._fin = true;
                header._reserved = 0;
                header._opcode = DataType;
                header._mask_flag = false;
                strongSelf->WebSocketSplitter::encode(header, buf);
            }
            return buf->size();
        });

        //允许websocket客户端
        return true;
    }

    /**
     * 开始收到一个webSocket数据包
     */
    void onWebSocketDecodeHeader(const WebSocketHeader &packet) override{
        //新包，原来的包残余数据清空掉
        _payload_section.clear();
    }

    /**
     * 收到websocket数据包负载
     */
    void onWebSocketDecodePayload(const WebSocketHeader &packet,const uint8_t *ptr,size_t len,size_t recved) override {
        _payload_section.append((char *)ptr,len);
    }

    /**
     * 接收到完整的一个webSocket数据包后回调
     * @param header 数据包包头
     */
    void onWebSocketDecodeComplete(const WebSocketHeader &header_in) override {
        WebSocketHeader& header = const_cast<WebSocketHeader&>(header_in);
        auto  flag = header._mask_flag;
        header._mask_flag = false;

        switch (header._opcode){
            case WebSocketHeader::CLOSE:{
                HttpSessionType::encode(header,nullptr);
                HttpSessionType::shutdown(SockException(Err_shutdown, "recv close request from client"));
                break;
            }
            
            case WebSocketHeader::PING:{
                header._opcode = WebSocketHeader::PONG;
                HttpSessionType::encode(header,std::make_shared<BufferString>(_payload_section));
                break;
            }
            
            case WebSocketHeader::CONTINUATION:
            case WebSocketHeader::TEXT:
            case WebSocketHeader::BINARY:{
                if (!header._fin) {
                    //还有后续分片数据, 我们先缓存数据，所有分片收集完成才一次性输出
                    _payload_cache.append(std::move(_payload_section));
                    if (_payload_cache.size() < MAX_WS_PACKET) {
                        //还有内存容量缓存分片数据
                        break;
                    }
                    //分片缓存太大，需要清空
                }

                //最后一个包
                if (_payload_cache.empty()) {
                    //这个包是唯一个分片
                    _session->onRecv(std::make_shared<WebSocketBuffer>(header._opcode, header._fin, std::move(_payload_section)));
                    break;
                }

                //这个包由多个分片组成
                _payload_cache.append(std::move(_payload_section));
                _session->onRecv(std::make_shared<WebSocketBuffer>(header._opcode, header._fin, std::move(_payload_cache)));
                _payload_cache.clear();
                break;
            }
            
            default: break;
        }
        _payload_section.clear();
        header._mask_flag = flag;
    }

    /**
     * 发送数据进行websocket协议打包后回调
    */
    void onWebSocketEncodeData(Buffer::Ptr buffer) override{
        HttpSessionType::send(std::move(buffer));
    }

private:
    string _payload_cache;
    string _payload_section;
    weak_ptr<Server> _weak_server;
    TcpSession::Ptr _session;
    Creator _creator;
};


template<typename TcpSessionType,typename HttpSessionType = HttpSession,WebSocketHeader::Type DataType = WebSocketHeader::TEXT>
class WebSocketSession : public WebSocketSessionBase<TcpSessionCreator<TcpSessionType>,HttpSessionType,DataType>{
public:
    WebSocketSession(const Socket::Ptr &pSock) : WebSocketSessionBase<TcpSessionCreator<TcpSessionType>,HttpSessionType,DataType>(pSock){}
    virtual ~WebSocketSession(){}
};

#endif //ZLMEDIAKIT_WEBSOCKETSESSION_H
