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
## 跨站脚本攻击 XSS (Cross Site Scripting) 

XSS攻击注入点：
* HTML节点内容  
可对用户输入进行转译处理

* HTML属性
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
* JavaScript代码
JavaScript中可以直接使用 `JSON.stringify( str )` 方法进行转译

* 富文本


## 跨站请求伪造 CSRF

**CSRF**：是一种常见的冒用用户身份的方法

## 前端 Cookoes 安全性

## 点击劫持

**点击劫持**：是一种常见的利用用户的身份，在用户不知情的情况下完成操作的一种攻击

## 传输过程安全问题

## 用户密码安全问题

## SQL注入攻击

## 信息泄露和社会工程学

## 其他安全问题