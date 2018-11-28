# Web 安全(Web Security)

> 前置知识：  
> * 原生 JavaScript
> * 少量 Node.js 基础
> * HTTP 基础知识( Cookies / Session )
> * Web 后端基础知识( HTTP / SQL )

* 私密性
* 可靠性
---
* 代码层面
* 架构层面
* 运维层面

---
## 1. 跨站脚本攻击 XSS (Cross Site Scripting) 

XSS攻击注入点：
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

### 1.3 [CSP](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CSP) (Content Security Policy)：内容安全策略
可指定可执行的内容。  
```html
<-这只是一个示例，具体的写法以及参数的意义请参见上方的链接->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
```

## 2. 跨站请求伪造 CSRF(Cross Site Request Forgy)

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
[[JS] js获取referer,兼容各种浏览器](https://www.51-n.com/t-4016-1-1.html)

## 3. 前端 [Cookies](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Cookies) 安全性

**Cookies**：前端数据存储，  
### 3.1  Cookies 的特点
* 前端数据存储
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
* http-only：Cookies 只能被 HTTP协议 使用。
* Secure：指定 Cookies 是否只能在 HTTPS 的网站中使用，指定后在 HTTP 的网站中则不能使用。
* SameSite：指定第三方网站的请求是否可以使用 Cookies。([2.1 SameSite Cookie，防止 CSRF 攻击](###-2.1-SameSite-Cookie,防止-CSRF-攻击))
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
* http-only 的 Cookies 不会被偷（[3.2 Cookies 的特性](###-3.2-Cookies-的特性)）

#### 3.5.3 Cookies 和 CSRF 的关系
* CSRF 利用了用户 Cookies
* 攻击站点无法读写 Cookies（[2.2 在前端页面加入验证信息](###-2.2-在前端页面加入验证信息)）
* 最好能阻止第三方使用 Cookies（[2.1 SameSite Cookie，防止 CSRF 攻击](###-2.1-SameSite-Cookie,防止-CSRF-攻击)）

### 3.6 Cookies 安全策略
* 签名防篡改（[3.5.1 生成用户凭证](####-3.5.1-生成用户凭证)）
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
* heep-only（防止XSS）（[3.2 Cookies 的特性](###-3.2-Cookies-的特性)）
* secure（防止传输过程中的窃听）（[3.2 Cookies 的特性](###-3.2-Cookies-的特性)）
* SameSite（[2.1 SameSite Cookie，防止 CSRF 攻击](###-2.1-SameSite-Cookie,防止-CSRF-攻击)）

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
* 辅助手段 [2.2 在前端页面加入验证信息](###-2.2-在前端页面加入验证信息)


## 5. 传输过程安全问题

## 6. 用户密码安全问题

## 7. SQL注入攻击

## 8. 信息泄露和社会工程学

## 9. 其他安全问题
