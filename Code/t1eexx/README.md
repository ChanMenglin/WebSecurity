# 启动项目

> 环境搭建：
> 1. 安装 Node.js：[Node.js 官网](https://nodejs.org/zh-cn/)
> 2. 安装 MySQL 数据库：[MySQL社区版下载地址](https://dev.mysql.com/downloads/mysql/)

1. 倒入数据
打开 MySQL 数据库 -> 执行以下命令
```sql
# 创建 safety 数据库
create database safety;
# 使用 safety 数据库
use safety;
```
2. 导入 [./safety.sql](./safety.sql)

3. 工具安装
```shell
# 安装 [`nodemon`](https://opencollective.com/nodemon/donate)，(可能需要管理员权限)
npm install nodemon -g
npm install jspm -g
```
4. 初始化项目：
```shell
# 在 t1eexx 目录下
jspm install
npm install
```
5. 启动项目
```shell
npm run dev
```
