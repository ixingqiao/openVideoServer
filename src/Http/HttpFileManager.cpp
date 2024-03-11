/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xia-chu/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#include <sys/stat.h>
#if !defined(_WIN32)
#include <dirent.h>
#endif //!defined(_WIN32)
#include <iomanip>
#include "HttpFileManager.h"
#include "Util/File.h"
#include "HttpConst.h"
#include "HttpSession.h"
#include "Common/Parser.h"
#include "Common/config.h"

namespace mediakit {

// hls的播放cookie缓存时间默认60秒，
// 每次访问一次该cookie，那么将重新刷新cookie有效期
// 假如播放器在60秒内都未访问该cookie，那么将重新触发hls播放鉴权
static int kHlsCookieSecond = 60;
static const string kCookieName = "ZL_COOKIE";
static const string kHlsSuffix = "/hls.m3u8";

class HttpCookieAttachment {
public:
    HttpCookieAttachment() {};
    ~HttpCookieAttachment() {};
public:
    //cookie生效作用域，本cookie只对该目录下的文件生效
    string _path;
    //上次鉴权失败信息,为空则上次鉴权成功
    string _err_msg;
    //本cookie是否为hls直播的
    bool _is_hls = false;

    //如果是hls直播，那么判断该cookie是否使用过MediaSource::findAsync查找过
    //如果程序未正常退出，会残余上次的hls文件，所以判断hls直播是否存在的关键不是文件存在与否
    //而是应该判断HlsMediaSource是否已注册，但是这样会每次获取m3u8文件时都会用MediaSource::findAsync判断一次
    //会导致程序性能低下，所以我们应该在cookie声明周期的第一次判断HlsMediaSource是否已经注册，后续通过文件存在与否判断
    bool _have_find_media_source = false;
};

const string &HttpFileManager::getContentType(const char *name) {
    return getHttpContentType(name);
}

static string searchIndexFile(const string &dir){
    DIR *pDir;
    dirent *pDirent;
    if ((pDir = opendir(dir.data())) == NULL) {
        return "";
    }
    set<string> setFile;
    while ((pDirent = readdir(pDir)) != NULL) {
        static set<const char *, StrCaseCompare> indexSet = {"index.html", "index.htm", "index"};
        if (indexSet.find(pDirent->d_name) != indexSet.end()) {
            string ret = pDirent->d_name;
            closedir(pDir);
            return ret;
        }
    }
    closedir(pDir);
    return "";
}

static bool makeFolderMenu(const string &httpPath, const string &strFullPath, string &strRet) {
    GET_CONFIG(bool, dirMenu, Http::kDirMenu);
    if (!dirMenu) {
        //不允许浏览文件夹
        return false;
    }
    string strPathPrefix(strFullPath);
    //url后缀有没有'/'访问文件夹，处理逻辑不一致
    string last_dir_name;
    if (strPathPrefix.back() == '/') {
        strPathPrefix.pop_back();
    } else {
        last_dir_name = split(strPathPrefix, "/").back();
    }

    if (!File::is_dir(strPathPrefix.data())) {
        return false;
    }
    stringstream ss;
    ss << "<html>\r\n"
          "<head>\r\n"
          "<title>文件索引</title>\r\n"
          "</head>\r\n"
          "<body>\r\n"
          "<h1>文件索引:";

    ss << httpPath;
    ss << "</h1>\r\n";
    if (httpPath != "/") {
        ss << "<li><a href=\"";
        ss << "/";
        ss << "\">";
        ss << "根目录";
        ss << "</a></li>\r\n";

        ss << "<li><a href=\"";
        if (!last_dir_name.empty()) {
            ss << "./";
        } else {
            ss << "../";
        }
        ss << "\">";
        ss << "上级目录";
        ss << "</a></li>\r\n";
    }

    DIR *pDir;
    dirent *pDirent;
    if ((pDir = opendir(strPathPrefix.data())) == NULL) {
        return false;
    }
    multimap<string/*url name*/, std::pair<string/*note name*/, string/*file path*/> > file_map;
    while ((pDirent = readdir(pDir)) != NULL) {
        if (File::is_special_dir(pDirent->d_name)) {
            continue;
        }
        if (pDirent->d_name[0] == '.') {
            continue;
        }
        file_map.emplace(pDirent->d_name, std::make_pair(pDirent->d_name, strPathPrefix + "/" + pDirent->d_name));
    }
    //如果是root目录，添加虚拟目录
    if (httpPath == "/") {
        GET_CONFIG_FUNC(StrCaseMap, virtualPathMap, Http::kVirtualPath, [](const string &str) {
            return Parser::parseArgs(str, ";", ",");
        });
        for (auto &pr : virtualPathMap) {
            file_map.emplace(pr.first, std::make_pair(string("虚拟目录:") + pr.first, File::absolutePath("", pr.second)));
        }
    }
    int i = 0;
    for (auto &pr :file_map) {
        auto &strAbsolutePath = pr.second.second;
        bool isDir = File::is_dir(strAbsolutePath.data());
        ss << "<li><span>" << i++ << "</span>\t";
        ss << "<a href=\"";
        //路径链接地址
        if (!last_dir_name.empty()) {
            ss << last_dir_name << "/" << pr.first;
        } else {
            ss << pr.first;
        }

        if (isDir) {
            ss << "/";
        }
        ss << "\">";
        //路径名称
        ss << pr.second.first;
        if (isDir) {
            ss << "/</a></li>\r\n";
            continue;
        }
        //是文件
        struct stat fileData;
        if (0 == stat(strAbsolutePath.data(), &fileData)) {
            auto &fileSize = fileData.st_size;
            if (fileSize < 1024) {
                ss << " (" << fileData.st_size << "B)" << endl;
            } else if (fileSize < 1024 * 1024) {
                ss << fixed << setprecision(2) << " (" << fileData.st_size / 1024.0 << "KB)";
            } else if (fileSize < 1024 * 1024 * 1024) {
                ss << fixed << setprecision(2) << " (" << fileData.st_size / 1024 / 1024.0 << "MB)";
            } else {
                ss << fixed << setprecision(2) << " (" << fileData.st_size / 1024 / 1024 / 1024.0 << "GB)";
            }
        }
        ss << "</a></li>\r\n";
    }
    closedir(pDir);
    ss << "<ul>\r\n";
    ss << "</ul>\r\n</body></html>";
    ss.str().swap(strRet);
    return true;
}

class SockInfoImp : public SockInfo{
public:
    typedef std::shared_ptr<SockInfoImp> Ptr;
    SockInfoImp() = default;
    ~SockInfoImp() override = default;

    string get_local_ip() override {
        return _local_ip;
    }

    uint16_t get_local_port() override {
        return _local_port;
    }

    string get_peer_ip() override {
        return _peer_ip;
    }

    uint16_t get_peer_port() override {
        return _peer_port;
    }

    string getIdentifier() const override {
        return _identifier;
    }

    string _local_ip;
    string _peer_ip;
    string _identifier;
    uint16_t _local_port;
    uint16_t _peer_port;
};

/**
 * 发送404 Not Found
 */
static void sendNotFound(const HttpFileManager::invoker &cb) {
    GET_CONFIG(string, notFound, Http::kNotFound);
    cb(404, "text/html", StrCaseMap(), std::make_shared<HttpStringBody>(notFound));
}

/**
 * 拼接文件路径
 */
static string pathCat(const string &a, const string &b){
    if (a.back() == '/') {
        return a + b;
    }
    return a + '/' + b;
}
////////////////////////////////////HttpResponseInvokerImp//////////////////////////////////////

void HttpResponseInvokerImp::operator()(int code, const StrCaseMap &headerOut, const Buffer::Ptr &body) const {
    return operator()(code, headerOut, std::make_shared<HttpBufferBody>(body));
}

void HttpResponseInvokerImp::operator()(int code, const StrCaseMap &headerOut, const HttpBody::Ptr &body) const{
    if (_lambad) {
        _lambad(code, headerOut, body);
    }
}

void HttpResponseInvokerImp::operator()(int code, const StrCaseMap &headerOut, const string &body) const{
    this->operator()(code, headerOut, std::make_shared<HttpStringBody>(body));
}

HttpResponseInvokerImp::HttpResponseInvokerImp(const HttpResponseInvokerImp::HttpResponseInvokerLambda0 &lambda){
    _lambad = lambda;
}

HttpResponseInvokerImp::HttpResponseInvokerImp(const HttpResponseInvokerImp::HttpResponseInvokerLambda1 &lambda){
    if (!lambda) {
        _lambad = nullptr;
        return;
    }
    _lambad = [lambda](int code, const StrCaseMap &headerOut, const HttpBody::Ptr &body) {
        string str;
        if (body && body->remainSize()) {
            str = body->readData(body->remainSize())->toString();
        }
        lambda(code, headerOut, str);
    };
}

void HttpResponseInvokerImp::responseFile(const StrCaseMap &requestHeader,
                                          const StrCaseMap &responseHeader,
                                          const string &filePath,
                                          bool use_mmap) const {
    StrCaseMap &httpHeader = const_cast<StrCaseMap &>(responseHeader);
    std::shared_ptr<FILE> fp(fopen(filePath.data(), "rb"), [](FILE *fp) {
        if (fp) {
            fclose(fp);
        }
    });

    if (!fp) {
        //打开文件失败
        GET_CONFIG(string, notFound, Http::kNotFound);
        GET_CONFIG(string, charSet, Http::kCharSet);

        auto strContentType = StrPrinter << "text/html; charset=" << charSet << endl;
        httpHeader["Content-Type"] = strContentType;
        (*this)(404, httpHeader, notFound);
        return;
    }

    auto &strRange = const_cast<StrCaseMap &>(requestHeader)["Range"];
    size_t iRangeStart = 0;
    size_t iRangeEnd = 0;
    size_t fileSize = File::fileSize(fp.get());

    int code;
    if (strRange.size() == 0) {
        //全部下载
        code = 200;
        iRangeEnd = fileSize - 1;
    } else {
        //分节下载
        code = 206;
        iRangeStart = atoll(FindField(strRange.data(), "bytes=", "-").data());
        iRangeEnd = atoll(FindField(strRange.data(), "-", nullptr).data());
        if (iRangeEnd == 0) {
            iRangeEnd = fileSize - 1;
        }
        //分节下载返回Content-Range头
        httpHeader.emplace("Content-Range", StrPrinter << "bytes " << iRangeStart << "-" << iRangeEnd << "/" << fileSize << endl);
    }

    //回复文件
    HttpBody::Ptr fileBody = std::make_shared<HttpFileBody>(fp, iRangeStart, iRangeEnd - iRangeStart + 1, use_mmap);
    (*this)(code, httpHeader, fileBody);
}

HttpResponseInvokerImp::operator bool(){
    return _lambad.operator bool();
}


}//namespace mediakit