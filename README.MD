# Web 安全(Web Security)

> 前置条件：  
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

### 1.2 HTML属性
```javascript
/**
 * 对 HTML 节点内容及属性进行 XSS 攻击的预防代码
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
### 1.3 JavaScript代码  
JavaScript中可以直接使用 `JSON.stringify( str )` 方法进行转译

### 1.4 富文本
采用过滤的方式进行防御
1. 黑名单过滤
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
2. 白名单过滤
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

### 1.5 [CSP](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CSP)：内容安全策略
可指定可执行的内容。



## 2. 跨站请求伪造 CSRF

**CSRF**：是一种常见的冒用用户身份的方法

## 3. 前端 Cookoes 安全性

## 4. 点击劫持

**点击劫持**：是一种常见的利用用户的身份，在用户不知情的情况下完成操作的一种攻击

## 5. 传输过程安全问题

## 6. 用户密码安全问题

## 7. SQL注入攻击

## 8. 信息泄露和社会工程学

## 9. 其他安全问题