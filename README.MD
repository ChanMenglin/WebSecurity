# Web 安全(Web Security)

> 前置知识：  
> * 原生 JavaScript
> * 少量 Node.js 基础
> * HTTP 基础知识( Cookies / Session )
> * Web 后端基础知识( HTTP / SQL )
> * SQL 及 关系型数据库 基础

[MDN Web 文档 - Web 安全](https://developer.mozilla.org/zh-CN/docs/Web/Security)

# 目录（Contents）

* [1. 跨站脚本攻击 XSS (Cross Site Scripting)](#1-跨站脚本攻击-xss-cross-site-scripting)
    * [1.1 HTML节点内容](#11-html节点内容)
        * [1.1.1 HTML属性](#111-html属性)
        * [1.1.2 JavaScript 代码](#112-javascript-代码)
    * [1.2 富文本](#12-富文本)
        * [1.2.1 黑名单过滤](#121-黑名单过滤)
        * [1.2.2 白名单过滤](#122-白名单过滤)
    * [1.3 CSP (Content Security Policy) 内容安全策略](#13-csp-content-security-policy-内容安全策略) 
* [2. 跨站请求伪造 CSRF (Cross Site Request Forgy)](#2-跨站请求伪造-csrf-cross-site-request-forgy)
    * [2.1 SameSite Cookie，防止 CSRF 攻击](#21-samesite-cookie防止-csrf-攻击)
    * [2.2 在前端页面加入验证信息](#22-在前端页面加入验证信息)
    * [2.3 通过 referer 禁止来自第三方网站的强求](#23-通过-referer-禁止来自第三方网站的强求)
* [3. 前端 Cookies 安全性](#3-前端-cookies-安全性)
    * [3.1 Cookies 的特点](#31-cookies-的特点)
    * [3.2 Cookies 的特性](#32-cookies-的特性)
    * [3.3 Cookies 操作](#33-cookies-操作)
    * [3.4 Cookies 作用](#34-cookies-作用)
    * [3.5 Cookies 安全问题](#35-cookies-安全问题)
        * [3.5.1 生成用户凭证](#351-生成用户凭证)
        * [3.5.2 Cookies 和 XSS 的关系](#352-cookies-和-xss-的关系)
        * [3.5.3 Cookies 和 CSRF 的关系](#353-cookies-和-csrf-的关系)
    * [3.6 Cookies 安全策略](#36-cookies-安全策略)
* [4. 点击劫持](#4-点击劫持)
    * [4.1 点击劫持的原理](#41-点击劫持的原理)
    * [4.2 点击劫持的前提](#42-点击劫持的前提)
    * [4.3 点击劫持的防御](#43-点击劫持的防御)
* [5. 传输过程安全问题](#5-传输过程安全问题)
    * [5.1 HTTP 传输窃听和篡改的危害](#51-http-传输窃听和篡改的危害)
    * [5.2 HTTPS TLS(SSL) 加密](#52-https-tlsssl-加密)
    * [5.3 部署 HTTPS 的网站](#53-部署-https-的网站)
* [6. 用户密码安全问题（接入层）](#6-用户密码安全问题接入层)
    * [6.1 密码的作用](#61-密码的作用)
    * [6.2 密码的存储](#62-密码的存储)
        * [6.2.1 密码的存储原则](#621-密码的存储原则)
        * [6.2.2 密码存储方案](#622-密码存储方案)
    * [6.3 密码的传输](#63-密码的传输)
        * [6.3.1 HTTPS传输](#631-https传输)
        * [6.3.2 频率限制（防猜解）](#632-频率限制防猜解)
        * [6.3.3 前端加密（作用有限）](#633-前端加密作用有限)
    * [6.4 密码的替代方案](#64-密码的替代方案)
* [7. SQL注入攻击](#7-sql注入攻击)
    * [7.1 SQL 注入危害](#71-sql-注入危害)
    * [7.2 SQL 注入防御](#72-sql-注入防御)
    * [7.3 NoSQL 注入和防御](#73-nosql-注入和防御)
* [8. 上传问题（接入层）](#8-上传问题接入层)
    * [8.1 上传文件的问题](#81-上传文件的问题)
    * [8.2 上传漏洞防御](#82-上传漏洞防御)
        * [8.2.1 限制上传后缀（有时不可靠）](#821-限制上传后缀有时不可靠)
        * [8.2.2 文件类型检查（可绕过）](#822-文件类型检查可绕过)
        * [8.2.3 文件内容检查（可欺骗）](#823-文件内容检查可欺骗)
        * [8.2.4 程序输出（防止文件被当作程序执行）](#824-程序输出防止文件被当作程序执行)
        * [8.2.5 权限控制 - 可写可执行互斥](#825-权限控制---可写可执行互斥)
* [9. 信息泄露和社会工程学](#9-信息泄露和社会工程学)
    * [9.1 信息泄露](#91-信息泄露)
    * [9.2 信息泄露的途径](#92-信息泄露的途径)
    * [9.3 信息保护](#93-信息保护)
* [10 安全策略](#10-安全策略)

## 1. 跨站脚本攻击 XSS (Cross Site Scripting)

XSS攻击原理：来自用户的数据被当作脚本在页面中执行  

### 1.1 HTML节点内容

可对用户输入进行转译处理

#### 1.1.1 HTML属性

```javascript
/**
 * 对 HTML 节点内容及属性进行 XSS 攻击的预防代码
 * 将 HTML 节点内容及属性转译为 HTML 实体
 * 适用于绝对禁止用户输入 HTML 内容的场景
 */
var escapeHTMLProperty = function( str ) {
    if (!str) return '';
    // & 的转译必须放在所有转译的最前面
    str = str.replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quto;')
        .replace(/'/g, '&#39;');
    // 一般不对空格进行转译
    // .replace(/ /g, '&#32;')
    return str;
}
```

#### 1.1.2 JavaScript 代码

JavaScript 中可以直接使用 `JSON.stringify( str )` 方法进行转译

### 1.2 富文本

采用过滤的方式进行防御

#### 1.2.1 黑名单过滤

```javascript
/**
* 采用 黑名单过滤 对富文本内容进行过滤
* 次方法的问题在于 XSS攻击 的变种很多，很难对所有情况进行逐一过滤
* 此处仅做演示，并不会用于真实环境
*/
var xssFilter = function ( html ) {
    if (!html) return '';
    html = html.replace(/<\s*\/?script\s*>/g, '') // 替换 <script> 标签
        .replace(/javascript:[^'"]*/g, ''); // 替换 javascript='' 的调用（常出现在 a 标签）
        .replace(/onerror\s*=\s*['"]?[^'"]*['"]?/g, '') // 替换 <img src=\'abc\' onerror=\'alert(1)\' /> 一类的攻击
    // 还有 SVG\Object 等 XSS攻击 手段还未进行过滤
    return html;
}
```

#### 1.2.2 白名单过滤

白名单过滤需要先解析 HTML。  
**方法一**：这里采用 [cheerio](https://cheerio.js.org) 这个库进行解析。(cheerio的使用与 jQuery 类似，比较容易上手)

```shell
# 安装 cheerio
npm install cheerio --save-dev
```

```javascript
/**
 * 采用 白名单过滤+cheerio 对富文本内容进行过滤
 * 需要维护白名单列表，有较好的定制化和灵活性
 */
var xssFilter = function ( html ) {
     if (!html) return '';
     // 白名单列表
     var whiteList = {
         'img': ['src'],
         'font': ['color', 'size'].
         'a': ['href'],
     };
    // 引入 cheerio
    var cheerio = require('cheerio');
    var $ = cheerio.load(html);
    $('*').each(function (index, e) {
        // 当标签名不在白名单中时，将其移除(name 为标签名)
        if (whiteList[e.name]) $(e).remove(); return;
        // 当标签名在白名单时，对其属性进行判断(attribs 为标签的属性集合)
        for (var attr in e.attribs) {
            // 当属性名不在相应标签的属性列表中时，将其移除
            // （cheerio 中将属性设为 null 即为移除该属性）
            if (whiteList[e.name].indexOf(attr) === -1) $(e).attr(attr, null);
        }
    })；
    return html;
}
```

**方法二**：使用第三方 XSS 白名单防御库 [js-xss](https://github.com/leizongmin/js-xss)

```shell
# 安装 js-xss
npm install xss --save-dev
```

```javascript
/**
 * 采用 白名单过滤+js-xss 对富文本内容进行过滤
 * 快捷、方便，灵活性较差，不需要/少量的白名单维护
 */
var xssFilter = function ( html ) {
    if (!html) return '';
    var xss = require('xss');
    return xss(html);
}
```

### 1.3 [CSP](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CSP) (Content Security Policy) 内容安全策略

CSRF原理：在用户不知情的倩况下冒充用户身份对目标网站发送请求。

可指定可执行的内容。

```html
<-这只是一个示例，具体的写法以及参数的意义请参见上方的链接->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
```

## 2. 跨站请求伪造 CSRF (Cross Site Request Forgy)

**CSRF**：是一种常见的冒用用户身份的方法  
> **攻击特点**：
> 1. B 网站向 A 网站请求
> 2. 请求带 A 网站 Cookies
> 3. 不访问 A 网站前端
> 4. referer 为 B 网站

### 2.1 SameSite Cookie，防止 CSRF 攻击

此方法可有效防止对用户身份( Cookies )的冒用，但仍然可以进行匿名攻击，需要对匿名用户的权限进行控制。(此方法的[兼容性](https://caniuse.com/#search=SameSite)不好)  
[SameSite Cookie，防止 CSRF 攻击](http://www.cnblogs.com/ziyunfei/p/5637945.html)  
[SameSite - OWASP](https://www.owasp.org/index.php/SameSite)

### 2.2 在前端页面加入验证信息

此方法可防止 CSRF 攻击中不访问被攻击网站前端的问题

1. 验证码

[ccap](https://github.com/DoubleSpout/ccap) 这是一个生成验证码的库。这种方式对用户体验有较大影响，不适宜大量使用。

2. token

```javascript
// 此变量为随机生成并取整，将会放在页面表单及Cookies中
var csrfToken = parseInt(Math.random() * 9999999, 10);
```

### 2.3 通过 referer 禁止来自第三方网站的强求

[[JS] js 获取 referer,兼容各种浏览器](https://www.51-n.com/t-4016-1-1.html)

## 3. 前端 [Cookies](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Cookies) 安全性

**Cookies**：前端数据存储

### 3.1 Cookies 的特点

* 前端数据存储（大小：4kb 左右）
* 后端可通过 http 头进行设置
* 请求时通过 http 头传给后端
* 前端可读写
* 遵守同源策略  
> 同源策略：对于 Cookies 而言，同一个源下的 Cookies 才能读写。  
> 源：当协议、域名、端口全部一致时才叫同源。

### 3.2 Cookies 的特性

* 域名：指定 Cookies 的使用范围。
* 有效期：指定 Cookies 的有效期，过期后就会失效。
* 路径：指定 Cookies 作用于网站上的哪一级，具体为 URL 的层级。可以为不同层级的 URL 设置不同的 Cookies，只有当这个层级的页面被访问时对应的 Cookies 才能被访问。
* http-only：Cookies 只能被 HTTP协议 使用，不能被 JavaScript 读取。
* Secure：指定 Cookies 是否只能在 HTTPS 的网站中使用，指定后在 HTTP 的网站中则不能使用。
* SameSite：指定第三方网站的请求是否可以使用 Cookies。([2.1 SameSite Cookie，防止 CSRF 攻击](#21-samesite-cookie防止-csrf-攻击))
> 浏览器开发者工具中查看 Cookies 信息：
> 在 浏览器的开发者工具 -> Application/存储空间 -> Cookies 就可以找到 Cookies 信息。
> * Name（名称）: 健
> * Value（值）: 值
> * Domain（域）: 域名
> * Path（路径）: 路径
> * Expires / Max-Age（过期时间）: 有效期（Session 表示只在会话内有效）
> * Size（大小）: 大小
> * HTTP（HTTP）: http-only
> * Secure（安全）: Secure
> * SameSite（相同站点）: SameSite（不是所有浏览器都有此属性）  
>
> 英文名称参考Google Chrome 70.0.3538.102（正式版本）（64 位）,中文名称参考Safari 浏览器12.0.1 (14606.2.104.1.1)

### 3.3 Cookies 操作

* 读取 Cookies：document.cookie
* 设置 Cookies 有效期：document.cookie = 'a=1;expires=Tue, 27 Nov 2018 03:40:29 GMT'
* 删除 Cookies：并没有删除 Cookies 的方法，但可以通过给 Cookies 的有效期设置一个过去的时间，就可以删除 Cookies。
> expires 的值为过期时间，且只能为此格式，此格式时间的快速获取方法：  
> ```javascript
> var d = new Date();
> d.toGMTString();
> ```

### 3.4 Cookies 作用

* 存储个性化设置
* 存储未登录时用户的唯一标识
* 存储已登陆用户的凭证
* 存储其他业务数据（页面缓存）

> Cookies - 登陆用户凭证
> * 前端提交用户信息
> * 后端验证用户信息
> * 后端通过 HTTP 头设置用户凭证
> * 后续访问时后端先验证用户凭证

### 3.5 Cookies 安全问题

#### 3.5.1 生成用户凭证

* 用户ID，使用用户ID作为用户的标示并不安全，有被篡改的风险
* 用户ID + 签名：可防止 用户ID 被篡改，Cookies 中会同时存储用户ID和签名，作为校验。

```javascript
// 加密签名模块
// crypto 为 NodeJs 自带的加密模块
import crypto from 'crypto';
var crypt = {};
// 随机的字符，越复杂越安全
const key = '#@56562366&##%';
crypt.cryptUserId = function( userId ) {
    var sign = crypto.createHmac('sha256', key)
    sing.update( userId + '' );
    return sign.digest( 'hex' );
}
export crypt;
```

* SessionId：在 Cookies 中不存储任何用户信息，后端可通过 SessionId 判断用户的身份

```javascript
/** 
* SessionId
*/ 
var session = {};
var cache = {};

session.set = function( userId, obj) {
    var sessionId = Math.random();
    if ( !cache[sessionId] ) {
        cache[sessionId] = {};
    }
    cache[sessionId].content = obj;
    return sessionId;
}

session.get = function( userId ) {
    return cache[sessionId] && cache[sessionId].content;
}
export session;
```

#### 3.5.2 Cookies 和 XSS 的关系

* XSS 可能偷取 Cookies
* http-only 的 Cookies 不会被偷（[3.2 Cookies 的特性](#32-Cookies-的特性)）

#### 3.5.3 Cookies 和 CSRF 的关系

* CSRF 利用了用户 Cookies
* 攻击站点无法读写 Cookies（[2.2 在前端页面加入验证信息](#22-在前端页面加入验证信息)）
* 最好能阻止第三方使用 Cookies（[2.1 SameSite Cookie，防止 CSRF 攻击](#21-samesite-cookie防止-csrf-攻击)）

### 3.6 Cookies 安全策略

* 签名防篡改（[3.5.1 生成用户凭证](#351-生成用户凭证)）
* 私有变换（加密）

```javascript
// node 中的加密
import crypto from 'crypto';

// 密钥
var key = '22e323##%&@%#$565';// 越复杂，越安全

// 加密
// 创建加密对象
var cipher = crypto.createCipher('des', key);
cipher.update('hello world', 'utf8', 'hex');
text += cipher.final('hex');

// 解密
// 创建解密对象
var decipher = crypto.createDecipher('des', key);
decipher.update(text, 'hex', 'utf8');
originalText += decipher.final('utf8');
// 加密和解密过程均为流式输出，因此要采用 += 接收，否则只会有部分内容。
```

* heep-only（防止XSS）（[3.2 Cookies 的特性](#32-Cookies-的特性)）
* secure（防止传输过程中的窃听）（[3.2 Cookies 的特性](#32-Cookies-的特性)）
* SameSite（[2.1 SameSite Cookie，防止 CSRF 攻击](#21-samesite-cookie防止-csrf-攻击)）

## 4. 点击劫持

**点击劫持**：是一种常见的利用用户的身份，在用户不知情的情况下完成操作的一种攻击
> 点击劫持的特点：
> * 用户操作，但不知情
> * 通过点击能进行的操作都可以通过点击劫持进行

### 4.1 点击劫持的原理

将目标网站作为一个 iframe 嵌入到攻击者网站中，并在视觉上进行隐藏（如调整透明度），用户看不见这个 iframe。对用户的点击进行引导，使用户进行一些指定的操作（如某种游戏），从而实现特定的目的（如银行转账）。  

### 4.2 点击劫持的前提

目标网站能够被攻击网站嵌套在 iframe 中。  

### 4.3 点击劫持的防御

未内嵌的网站与内嵌网站的区别在于，未内嵌的网站的 `top === window` 和 `top.location === window.location` 均为 `true`。而在 iframe 中 `top` 指向最外层的 `window`，`window` 指向 iframe 本身，结果为 `false`。

* JavaScript 禁止内嵌

```javascript
/** 
* JavaScript 禁止内嵌
* 此方法的问题在于 HTML5 iframe 中有一个新的属性
* [sandbox](https://developer.mozilla.org/zh-CN/docs/Web/HTML/Element/iframe)
* sandbox='allow-forms' 时可以正常提交表单，但不会执行脚本，导致此方法失效
*/
if ( top.location !== window.location ) {
    top.location = window.location;
}
```

* [X-FRAME-OPTIONS](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/X-Frame-Options) 禁止内嵌（推荐）
* 辅助手段 [2.2 在前端页面加入验证信息](#22-在前端页面加入验证信息)

* IFrame 安全策略（允许内嵌）

[IFrame 沙盒](https://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/)

## 5. 传输过程安全问题

HTTP 传输窃听和篡改：由于 HTTP 采用明文传输信息，导致请求发送过程中的所有设备（浏览器、代理服务器、链路、服务器等）均可读取甚至篡改发送的数据。

```bash
# 查看向一个 url 发送请求时会经过那些中间节点
# 其中所展示的任何一个节点均可进行 HTTP 传输窃听和篡改
# Mac OS/Linux
traceroute url
# Windows
tracert url
```

### 5.1 HTTP 传输窃听和篡改的危害

* 窃听通过网络传输的一切信息，包括敏感信息（账号、密码等）
* 插入广告
* 重定向网站（如钓鱼网站）
* 无法防御的 XSS 和 CSRF 攻击

### 5.2 HTTPS TLS(SSL) 加密

确认服务器身份的原理：

1. 浏览器 -> CA 获取内置信任列表
2. 服务器 -> CA 申请证书
3. CA -> 服务器 验证域名，颁发证书
4. 浏览器 -> 服务器 发起请求
5. 服务器 -> 浏览器 出具证书
6. 浏览器 验证通过

CA 安全的原则：

* 证书无法伪造
* 这书私钥不能泄露
* 域名管理权不能泄露
* CA 遵守原则

> 浏览器开发者工具中查看 这书 信息：
> 在 浏览器的开发者工具 -> Security 点击 View Certificate 就可以查看 这书 信息。
> 
> Mac OS 中查看本机中受信任的证书：
打开 钥匙串访问（keycha）程序 -> 系统跟证书 就可以查看系统中所有受信任的证书

### 5.3 部署 HTTPS 的网站

[https配置与部署 - 向上爬的蜗牛 - CSDN博客](https://blog.csdn.net/abld99/article/details/74011487)

## 6. 用户密码安全问题（接入层）

### 6.1 密码的作用

证明用户身份：将存储的密码与输入的密码进行比对以确认用户身份。  

**密码的泄露渠道**

* 数据库被盗
* 服务器被入侵
* 通许被窃听
* 内部人员泄露数据
* 其他网站（撞库）：多网站采用相同的账号密码，一个被盗殃及其他

### 6.2 密码的存储

#### 6.2.1 密码的存储原则

* 严禁明文存储（防泄漏）
* 单向变换（防泄漏）
* 变换复杂度要求（防猜解）
* 密码复杂度要求（防猜解）
* 加盐（防猜解）

#### 6.2.2 密码存储方案

1. 哈希算法（信息摘要）
* 明文 - 密文 一一对应
* 雪崩效应：明文的些许差异会导致完全不同的密文
* 密文 - 明文 无法反推
* 密文是固定的长度
* 常见的哈希算法：[md5](https://zh.wikipedia.org/zh-hans/MD5) | [sha1](https://zh.wikipedia.org/wiki/SHA-1) | [sha256](https://zh.wikipedia.org/wiki/SHA-2)

[单向变换彩虹表](https://cmd5.com) 会导致简单的密码及加密变得不安全。由于彩虹表的计算及存储限制，使用复杂的密码（长度 + 复杂度）即可大幅减少密码被反推的威胁。  

2. 帮助用户加强复杂度：
* 多级加密（防止彩虹表反推）
* 增加密码长度：在用户密码的基础上增加固定的字符（防止彩虹表反推）
* 加盐：增加用户唯一的字符（提高安全性）

> 多级（嵌套）加密的好处：
> * 变换越多越安全
> * 加密成本几乎不变（密码的生成会慢一些）
> * 彩虹表失效（密码足够复杂）
> * 解密成本倍增（更安全）

```javascript
/**
* 密码加密
* 这里只做了两次加密，不是很安全
* 实际项目中可使用多协议多次加密，可提高安全性
*/
import crypt from 'crypto';
let password = {};

const md5 = (str) => {
    const md5Hash = crypt.createHash('md5');
    md5Hash.update(str);
    return md5Hash.digest('hex');
}

const salt = () => {
    // 这里采用硬编码添加字符串，字符串一旦添加不能改变且越复杂越安全
    return md5(Math.random() + 999999 + 'fd4fb5 e#687f%$@_%%$#32' + new Date().getTime());
}

password.encryptPassword = (password) => {
    return md5(salt + password);
}

export password;
```

### 6.3 密码的传输

#### 6.3.1 HTTPS传输

[5.3 部署 HTTPS 的网站](#53-部署-HTTPS-的网站)

#### 6.3.2 频率限制（防猜解）

此处不做说明

#### 6.3.3 前端加密（作用有限）

添加 [js-md5](https://github.com/emn178/js-md5) 模块

```bash
npm install -save-dev js-md5
```

```javascript
import md5 from 'js-md5';
// 此处只是示例，可增加加密字符串的复杂度以提高安全性
const password = md5(password)
```

### 6.4 密码的替代方案

1. 生物特征密码
    * 指纹
    * 声纹
    * 虹膜
    * 人脸识别

生物特征密码的问题：

* 私密性 - 容易泄露
* 安全性 - 碰撞（生物识别采用相似性进行匹配，并不能保证完全匹配）
* 唯一性 - 终身唯一，无法改变（一旦被破解很难改变）

## 7. SQL注入攻击

### 7.1 SQL 注入危害

* 猜解密码
* 获取数据
* 删库删表
* 拖库

### 7.2 SQL 注入防御

* 关闭错误输出（不要将错误信息抛到前台，应做模糊处理）
* 检查数据类型（对传入 SQL 的数据做类型检查，包括用户输入的和层序获取的，以防篡改）
* 对数据进行转译（转译不能防止所有的 SQL 注入）

```javascript
const mysql = require('mysql');
exports.getConnection = function(){
    /** 
     * 此为 Mysql 对象
    */
    let connection = mysql.createConnection({
        host: 'localhost',
        database: 'safety',
        user: 'root',
        password: '123456789'
    });
    connection.connect();
    return connection;
};

// 参数转译方法
connection.escape(id);
// 一、转译 SQL 语句
`select * from table where id = ${ connection.escape(id) }`
// 二、通过类似参数化查询，在传递参数前会进行转译
`select * from table where id ?`, [id]
```

* 使用参数化查询（避免 SQL 注入威胁）  

[mysql2](https://github.com/brianmario/mysql2) 可以支持 MySQL 参数化查询，从而避免 SQL 注入的威胁。mysql2 为第三方工具，向下兼容 mysql

* 使用 [ORM（对象关系映射）](https://zh.wikipedia.org/wiki/%E5%AF%B9%E8%B1%A1%E5%85%B3%E7%B3%BB%E6%98%A0%E5%B0%84)  

[Sequelize](https://demopark.github.io/sequelize-docs-Zh-CN/) | [Github](https://github.com/sequelize/sequelize) ：是一个Node.js ORM, 目前支持 Postgres, MySQL, SQLite 和 Microsoft SQL Server.  
安装 Sequelize

```bash
# 安装 Sequelize
npm install --save-dev Sequelize
# 还有以下之一:
$ npm install --save pg pg-hstore // Postgres
$ npm install --save mysql2 // MySQL
$ npm install --save sqlite3 // SQLite
$ npm install --save tedious // MSSQL
```

```javascript
/**
 * sequelize.js
 * Sequelize 实例
 * 此处引入的为刚才安装的 sequelize 第三方库
 */
import Sequelize from 'sequelize';

let sequelize = new Sequelize({
    host: 'localhost',
    database: 'safety',
    username: 'root',
    define: {
        freezeTableName: true,
    },
});
export sequelize;
// -------------------------------------------
/**
 * Post.js
 * 使用 Sequelize 定义的数据模型
 * 此处引入的为刚才创建的 sequelize 实例sequelize.js，
 * 此处一定注意区分
 */
import sequelize from './sequelize'; // 实例
import Sequelize from 'sequelize'；// 模块

var Post = sequelize.define('post', {
    // 字段
},
{
    // 此处可不加
    // 如果添加 则为指定表名
    // 如果不加 sequelize 会尝试对应表名
    tableName: 'post'.
});
export Post;
```

### 7.3 NoSQL 注入和防御

[mongoose](https://mongoosejs.com) | [Github](https://github.com/Automattic/mongoose)

## 8. 上传问题（接入层）

### 8.1 上传文件的问题

* 文件由用户上传
* 用户能够通过 Url 访问上传的文件
* 访问时文件可能会当作程序执行

### 8.2 上传漏洞防御

#### 8.2.1 限制上传后缀（有时不可靠）

```javascript
/**
* 禁止用户上传 JS 文件（有时此方法会不可靠）
* 此处只做演示，在 Nodejs 环境中几乎没有上传漏洞
* 但在如 PHP 中，上传漏洞较为严重
* 不同语言的文件处理不同，需要不同的防御方式
*/
import path from 'path';
// file 为上传的文件对象
// 此处为取文件后缀名
const ext = path.extname(file.name);
if (ext === 'js') throw new Error('不能上传js文件');
```

### 8.2.2 文件类型检查（可绕过）

```javascript
/**
* 文件类型检查（此方法为浏览器提供，可绕过）
* 不同语言的文件处理不同，需要不同的防御方式
*/
if (file.type !== 'image/png') throw new Error('上传的文件类型错误');
```

### 8.2.3 文件内容检查（可欺骗）

```javascript
/** 
* 文件内容检查（可欺骗）
* 由于同一类型文件的前几位二进制位是相同的，可以根据此特性进行判断
* 但可通过修改文件前几位让层序误判文件类型
*/
import fs from 'fs';

const fileBuffer = fs.readFileSync(file.path);
fileBuffer[0] == ox5b;
```

### 8.2.4 程序输出（防止文件被当作程序执行）

在访问莫文件时不直接输出，而是通过程序读取文件再输出，从而阻止了文件的执行。Node.js 的 fs 模块就是采用的这种方式，因此在 Node.js 中几乎不存在上传文件漏洞，在其他环境中可以使用此方法进行防御。此方法会有一定的性能损失。

```javascript
import fs from 'fs';

fs.readFileSync(filePath);
```

#### 8.2.5 权限控制 - 可写可执行互斥

对目录文件权限进行控制，可写（如用户上传的文件）目录中的不给予执行权限，可执行（如程序文件）目录不给予写入权限，防止攻击中篡改和注入。

## 9. 信息泄露和社会工程学

### 9.1 信息泄露

* 泄露系统的敏感信息
* 泄露用户的敏感信息

### 9.2 信息泄露的途径

* SQL注入
* XSS / CSRF
* 错误信息失控：将错误信息直接暴露
* 水平权限控制不当：系统中用户权限管理不当

### 9.3 信息保护

[OAuth 思想](https://zh.wikipedia.org/wiki/%E5%BC%80%E6%94%BE%E6%8E%88%E6%9D%83)~

* 一切行为由用户授权
* 授权行为不泄露敏感信息（请求授权的网站只能拿到 token，根据此 token 确认用户身份）
* 授权会过期

使用 OAuth 思想 防止数据泄露

* 用户授权读取资料
* 无授权资料不可读取
* 不允许批量获取数据
* 数据接口可风控审计

## 10 安全策略

1. [内容安全策略简介](https://www.html5rocks.com/en/tutorials/security/content-security-policy/)  
2. [IFrame 沙盒](https://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/)

---

[context](https://www.contextis.com/en/resources)
