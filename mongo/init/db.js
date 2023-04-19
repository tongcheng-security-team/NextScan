db.createCollection("Engine_Config");
db.createCollection("Engine_Category");
db.createCollection("Message_Template");
db.createCollection("System_Menu");
db.createCollection("System_Role");
db.createCollection("System_RoleMenu");
db.createCollection("System_User");
db.createCollection("System_UserRole");
db.System_Role.insert([
    {
        "_id": ObjectId("5e36ddf74da8ad2e24fb5f51"),
        "roleName": "系统超级管理员",
        "roleCode": "system_admin",
        "desc": "系统超级管理员",
        "createBy": "",
        "updateBy": "",
        "updateTime": ISODate("2021-05-19T14:57:01.224Z"),
        "createTime": ISODate("2021-05-19T07:33:51.228Z")
    }
]);
db.System_User.insert([
    {
        "_id": ObjectId("5db002504da8ad2e24d0052d"),
        "username": "admin",
        "realname": "管理员",
        "workNo": "00001",
        "password": "c27e5dd2dc4a8b784fa22404196c74e3",
        "desc": "系统默认账户",
        "avatar": "",
        "sex": 1,
        "phone": "18888888888",
        "email": "nextscan@163.com",
        "createBy": "",
        "updateBy": "",
        "updateTime": ISODate("2023-02-14T08:21:15.220Z"),
        "createTime": ISODate("2021-05-18T07:33:51.228Z"),
        "status": 1
    }
]);

db.System_UserRole.insert([
    {
        "_id": ObjectId("63eb447bdafffcbd58344fa9"),
        "userId": "5db002504da8ad2e24d0052d",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    }
]);


db.Message_Template.insert([{
    "_id": ObjectId("6310636a69b35a49e396ffe8"),
    "name": "黑盒扫描器任务完成提醒",
    "code": 2,
    "type": 2,
    "content": "<h3>Hi, ${userName} 您好!</h3>\n<div style=\"line-height: 30pt; font-size: 12pt;\">\n<p>您提交的黑盒漏洞扫描任务【${projectName}】已经完成，共发现 ${total} 漏洞，其中严重漏洞 ${critical} 个、 高危漏洞${high}个、中危漏洞${medium}个、低危${low}个。</p>\n<p>任务详情点击：${url}，请您尽快处理</p>\n</div>",
    "createBy": "5db002504da8ad2e24d0052d",
    "updateBy": "5db002504da8ad2e24d0052d",
    "updateTime": ISODate("2023-02-16T10:59:48.833Z"),
    "createTime": ISODate("2022-09-01T07:46:50.913Z"),
    "enable": true,
    "subject": "黑盒扫描器任务完成"
}, {
    "_id": ObjectId("63849d3169b35abc2d329504"),
    "name": "agent离线通知",
    "code": 1,
    "type": 3,
    "content": "【黑盒漏洞扫描系统-节点离线告警】\n\n节点IP：${ip}\n节点类型：${type}\n节点环境：${group}\n离线时间：${time}\n",
    "createBy": "5db002504da8ad2e24d0052d",
    "updateBy": "5db002504da8ad2e24d0052d",
    "updateTime": ISODate("2023-02-08T02:34:08.602Z"),
    "createTime": ISODate("2022-11-28T11:36:17.193Z"),
    "enable": true,
    "subject": "节点离线通知"
}, {
    "_id": ObjectId("63105f5a69b35a49e396ffe7"),
    "name": "黑盒扫描任务完成提醒",
    "code": 2,
    "type": 3,
    "content": "【黑盒漏洞扫描系统】\n\n您提交的黑盒漏洞扫描任务【${projectName}】已经完成，共发现 ${total} 漏洞，详情请点击查看 ${url}",
    "createBy": "5db002504da8ad2e24d0052d",
    "updateBy": "5db002504da8ad2e24d0052d",
    "updateTime": ISODate("2023-02-08T02:34:14.450Z"),
    "createTime": ISODate("2022-09-01T07:29:30.004Z"),
    "enable": true,
    "subject": "黑盒扫描器任务完成"
}, {
    "_id": ObjectId("63886a2b69b35a7f53fe4da2"),
    "name": "任务失败通知",
    "code": 3,
    "type": 2,
    "content": "<p>您好，${userName}：</p>\n<p>您创建的扫描项目<strong>【${projectName}】</strong>任务执行失败，点击可查看项目详情：${url}</p>\n<p>失败原因：${err}</p>",
    "createBy": "",
    "updateBy": "5db002504da8ad2e24d0052d",
    "updateTime": ISODate("2022-12-14T06:35:06.999Z"),
    "createTime": ISODate("2022-12-01T08:47:39.156Z"),
    "enable": true,
    "subject": "黑盒扫描器任务失败"
}, {
    "_id": ObjectId("6388685969b35a7f53fe4da1"),
    "name": "任务失败通知",
    "code": 3,
    "type": 3,
    "content": "您好，${userName}：\n\n您创建的扫描项目 【${projectName}】 任务执行失败，点击可查看项目详情：${url}\n失败原因：${err}\n",
    "createBy": "",
    "updateBy": "5db002504da8ad2e24d0052d",
    "updateTime": ISODate("2023-02-08T02:34:21.017Z"),
    "createTime": ISODate("2022-12-01T08:39:53.039Z"),
    "enable": true,
    "subject": "任务失败"
}]);


db.Engine_Config.insert([
    {
        "_id": ObjectId("619c992069b35a8c86b6ec3b"),
        "group": 2,
        "proxyUrl": "",
        "proxySocksUrl": "",
        "maxHostError": 0,
        "concurrency": 500,
        "timeout": 10,
        "retries": 0,
        "rateLimitMinute": 1000,
        "pageTimeout": 30,
        "interactshUrl": "https://oast.me",
        "interactshToken": "",
        "interactionsCacheSize": 60,
        "interactionsPollDuration": 30,
        "interactionsEviction": 120,
        "interactionsColldownPeriod": 30,
        "headless": true,
        "systemResolvers": false,
        "interactsh": true,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2022-12-20T10:00:20.512Z"),
        "createTime": ISODate("2021-11-23T07:32:48.135Z"),
        "MaxHostError": 0,
        "ProxySocksURL": "",
        "rateLimit": 0,
        "headers": [
            {
                "key": NumberLong(1651745992515),
                "name": "User-Agent",
                "value": "NextScanner/1.0"
            }
        ],
        "extraHeadersString": "",
        "ignoreKeywords": [
            "delete",
            "logout",
            "quit",
            "exit"
        ],
        "maxTabsCount": 10,
        "pathByFuzz": false,
        "pathFromRobots": true,
        "tabRunTimeout": 30,
        "maxCrawlCount": 500,
        "domLoadedTimeout": 10
    }, {
        "_id": ObjectId("619c98f069b35a8c86b6ec3a"),
        "group": 1,
        "proxyUrl": "",
        "proxySocksUrl": "",
        "maxHostError": 0,
        "concurrency": 100,
        "timeout": 10,
        "retries": 0,
        "rateLimitMinute": 1000,
        "pageTimeout": 30,
        "interactshUrl": "https://oast.me",
        "interactshToken": "",
        "interactionsCacheSize": 60,
        "interactionsPollDuration": 30,
        "interactionsEviction": 60,
        "interactionsColldownPeriod": 30,
        "headless": true,
        "systemResolvers": false,
        "interactsh": true,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-02-16T10:51:45.033Z"),
        "createTime": ISODate("2021-11-23T07:32:00.013Z"),
        "MaxHostError": 0,
        "ProxySocksURL": "",
        "rateLimit": 0,
        "headers": [
            {
                "key": NumberLong(1651741016192),
                "name": "User-Agent",
                "value": "NextScanner/1.0"
            }
        ],
        "extraHeadersString": "",
        "ignoreKeywords": [
            "delete",
            "logout",
            "quit",
            "exit"
        ],
        "maxTabsCount": 10,
        "tabRunTimeout": 30,
        "pathByFuzz": false,
        "pathFromRobots": true,
        "maxCrawlCount": 100,
        "domLoadedTimeout": 10
    }
]);
db.Engine_Category.insert([
    {
        "_id": ObjectId("63bfd0c069b35a18580fbf91"),
        "name": "WEB漏洞",
        "sortNo": 0.0,
        "pid": "",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:20:00.838Z"),
        "createTime": ISODate("2023-01-12T09:20:00.838Z")
    },
    {
        "_id": ObjectId("63bfd0c069b35a18580fbf92"),
        "name": "服务器漏洞",
        "sortNo": 1.0,
        "pid": "",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:20:00.838Z"),
        "createTime": ISODate("2023-01-12T09:20:00.838Z")
    },
    {
        "_id": ObjectId("63bfd0c069b35a18580fbf95"),
        "name": "移动及IOT",
        "sortNo": 5.0,
        "pid": "",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:20:00.838Z"),
        "createTime": ISODate("2023-01-12T09:20:00.838Z")
    },
    {
        "_id": ObjectId("63bfd0c069b35a18580fbf96"),
        "name": "其他",
        "sortNo": 6.0,
        "pid": "",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:20:00.838Z"),
        "createTime": ISODate("2023-01-12T09:20:00.838Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416da5"),
        "name": "服务端模板注入",
        "desc": "SSTI(Server Side Template Injection) 服务器模板注入漏洞，指服务端接收外部恶意内容并将其作为Web应用模板的一部分，在对目标进行编译渲染的过程中，执行了模板内容里面的恶意内容，从而造成漏洞，SSTI 漏洞存在于 MVC 模式当中的 View 层。该漏洞影响范围主要取决于模版引擎的复杂性，常见有敏感信息泄露、代码执行、命令执行等危害。",
        "sortNo": -4.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "① 禁止使用格式化字符串结合字符串拼接的模板渲染方式，建议使用规范的模版渲染方式；\n② 对用户提交的数据进行过滤，避免用户输入的恶意字符被带入到模板中执行。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416da6"),
        "name": "反射型XSS",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "反射xss是由外部输入恶意JavaScript 代码，前端触发执行这些代码。通过引诱用户点击一个链接到目标网站的恶意链接，受害者前端会执行页面嵌入的恶意脚本，从而达到恶意攻击的目，例如，cookie、账户信息；也可以以受害者的身份执行一些恶意操作",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416da7"),
        "name": "存储型XSS",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "存储xss指的是攻击者利用应用程序提供的添加、修改数据功能，将恶意数据存储到服务器数据库或文件中，当其他用户浏览展示该数据的页面时，前端会执行页面嵌入的恶意脚本，从而达到恶意攻击的目的",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416da8"),
        "name": "基于DOM的XSS",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "dom型xss是基于DOM文档对象模型的一种漏洞，与反射xss不同的是dom型xss不经过后端。在 html 页面中，未通过规范 JavaScript 直接操作用户输入的数据，当攻击者插入一段恶意代码，页面加载完之后会执行这段恶意脚本，从而达到恶意攻击的目的。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416da9"),
        "name": "CSRF",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "跨站请求伪造漏洞（Cross-site request forgery，简称 CSRF），攻击者利用受害者身份发起 HTTP 请求，导致受害者在不知情的情况下进行了业务操作，如修改资料、提交订单、重置密码、发布留言或评论等敏感操作。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416daa"),
        "name": "SQL注入",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "SQL注入是网络攻击中较为常见的攻击方式，通过向代码层的SQL逻辑中注入恶意的SQL语句，并带入到服务器数据库执行，改变原有逻辑实现在数据库执行恶意 SQL 命令的效果，攻击者甚至可以利用数据库内部函数或缺陷进行权限提升，从而获取到服务器权限。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dab"),
        "name": "命令执行",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "在某种开发需求中，应用程序需要引入对系统本地命令的支持来完成特定功能，代码未对输入做过滤，导致执行命令的参数被用户完全可控，出现命令执行漏洞",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dac"),
        "name": "上传漏洞",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "文件上传漏洞是指服务端处理用户上传时，未对上传的文件进行合法性验证，攻击者上传恶意文件到服务器上运行，以达到获取服务器系统权限的目的。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dad"),
        "name": "信息泄漏",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "对当前用户进行鉴权，删除受影响文件，避免信息泄漏。",
        "riskDesc": "敏感信息的暴露会提供给攻击者更多的可用信息，引起更多被侵入的风险。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dae"),
        "name": "文件包含",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "1 避免由外界指定文件名\n2 文件名中不可以包含目录名 ，没有../ 的权限\n3 限定文件名中仅包含字母与数字",
        "riskDesc": "当应用程序使用攻击者控制的变量建立一个可执行代码的路径，允许攻击者控制运行时执行哪个文件时，就会导致文件包含漏洞。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416daf"),
        "name": "权限绕过",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "代码在处理数据的增、删、改、查时对客户端请求的数据过分相信而遗漏了权限的判定，导致了越权漏洞，攻击者利用越权漏洞可直接访问用户敏感信息，例如订单、个人信息、支付信息等，甚至对数据进行篡改、删除等操作。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db0"),
        "name": "URL跳转",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "URL 跳转攻击（URL Redirection），Web业务系统接收到用户提交的 URL 参数后，未对该参数进行“可信URL”校验就直接跳转到该 URL。如果 ly.com下某个 Web 业务系统存在 URL 跳转漏洞，攻击者向用户发送一个存在 URL 跳转漏洞的链接，该链接跳转到钓鱼网站页面，可能会导致用户被钓鱼攻击。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db1"),
        "name": "逻辑漏洞",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "严格控制当前用户权限",
        "riskDesc": "由于程序逻辑不严或逻辑太复杂，导致一些逻辑分支不能够正常处理或处理错误，一般出现在任意密码修改（没有旧密码验证）、越权访问、密码找回、交易支付金额等",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db2"),
        "name": "XML外部实体注入",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "XML 外部实体注入漏洞（XML External Entity），又叫XXE漏洞，它经常发生在应用程序解析XML输入时，由于允许外部实体的加载，攻击者利用该漏洞构造恶意内容，可导致任意文件读取、命令执行、攻击内网等危害。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db3"),
        "name": "文件读取、下载",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "应用系统在处理文件下载、读取时未对文件名做过滤，攻击者利用路径回溯符“../”跳出程序本身的限制目录实现目录跳转，导致服务器目录遍历、任意文件下载等安全问题。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db4"),
        "name": "JSON劫持",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "JSONP劫持漏洞是攻击者伪造 JSONP 调用页面，诱导被攻击者访问来达到窃取用户敏感数据的目的；jsonp 数据劫持就是攻击者获取了本应该传给网站其他接口的敏感数据。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db5"),
        "name": "登录爆破/认证缺陷",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "程序存在逻辑问题，不存在防刷机制导致的爆破、枚举等问题",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db6"),
        "name": "SSRF",
        "desc": "SSRF(Server-Side Request Forgery) 服务器端请求伪造漏洞，攻击者构造由服务端发起请求的安全漏洞。由于服务端提供了从其他应用获取数据的功能且没有对目标地址做过滤与限制（比如从指定 URL 获取网页文本内容、加载指定地址的图片等），攻击者就可以通过web服务器向其他服务器发出恶意请求。",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "由于SSRF漏洞从服务端发起，所以能够请求到与它相连而与外网隔离的内部系统，该漏洞常见危害有：\n● 扫描企业内部网络\n● 向内外部主机的发送精心构造的数据包，进行漏洞利用\n● 利用file协议读取服务器敏感文件\n● 利用gopher、dict协议，通过redis、memcache等服务获取服务器权限\n● DOS（如：请求大文件，始终保持连接），消耗服务器资源",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db7"),
        "name": "通用组件漏洞",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "系统使用带有漏洞的Java组件，可能造成严重的数据丢失或服务器接管。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db8"),
        "name": "目录遍历",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "1.设置固定的路径访问（不可预测）\n2.将内容防止线下\n3.正确配置nginx/apache",
        "riskDesc": "攻击者可以利用该漏洞遍历服务器目录及文件，获取敏感信息",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416db9"),
        "name": "管理后台对外",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "1.敏感系统迁至内网\n2.无法迁至内网的，需要确认外网登录界面弱口令及不存在其他安全问题",
        "riskDesc": "内部管理系统后台对外开放，存在进入后台可能性",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dba"),
        "name": "弱口令",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "攻击者利用系统弱口令获取特定账户或应用的权限，通过进一步攻击利用可能获取服务器权限，同时也可以批量获取系统敏感数据，造成数据泄露。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dbb"),
        "name": "CRLF",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "过滤 \\r ，\\n(%0d，%0a) 之类的行结束符，避免输入的数据污染其他 HTTP 首部字段。",
        "riskDesc": "攻击者可以利用crlf漏洞构造xss或url跳转",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dbc"),
        "name": "CORS劫持",
        "desc": "CORS是跨域资源共享（Cross-Origin Resource Sharing）的缩写。在配置跨域策略时未对请求源做合理的限制，使所有源都可以跨域访问该接口数据。这样就导致了cors跨域漏洞",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "cors漏洞一般用于窃取用户敏感数据，攻击者精心构造恶意页面指向存在CORS漏洞的接口，受害者点击此页面后攻击者就可以获取到当前目标所在页面的个人敏感数据。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dbd"),
        "name": "后门",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "删除该后门并进行排查",
        "riskDesc": "攻击者可以直接利用后门执行命令",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc0"),
        "name": "短信轰炸",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "系统发送短验接口未作限制，攻击者可以无限制调用接口进行短信轰炸。消耗短信资源和骚扰用户导致企业财产、声誉损失；",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc1"),
        "name": "多线程并发",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "在对敏感资源进行操作的场景中，如抽奖、下单、领取优惠券等，在短时间内多次进行相同请求时，服务端在业务处理过程中，对关键数据操作并未保证原子性，导致产生并发问题。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc2"),
        "name": "Java反序列化",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "Java程序使用ObjectInputStream对象的readObject方法将反序列化数据转换为java对象。但当输入的反序列化的数据可被用户控制，那么攻击者即可通过构造恶意输入，让反序列化产生非预期的对象，在此过程中执行构造的任意代码。",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc3"),
        "name": "配置错误",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "riskDesc": "应用配置错误可能导致验证的信息泄露、内网沦陷事件",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc4"),
        "name": "其他",
        "sortNo": 1.0,
        "pid": "63bfd0c069b35a18580fbf91",
        "advice": "其他",
        "riskDesc": "其他",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.899Z"),
        "createTime": ISODate("2023-01-12T09:26:06.899Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc5"),
        "name": "远程代码执行",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf92",
        "advice": "及时更新系统补丁，关闭敏感端口",
        "riskDesc": "攻击者可以直接远程控制服务器进行敏感命令操作",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.900Z"),
        "createTime": ISODate("2023-01-12T09:26:06.900Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc6"),
        "name": "配置缺陷",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf92",
        "advice": "及时更改配置，确保配置符合安全要求",
        "riskDesc": "存在信息泄露的可能性，攻击者可以根据该信息进行进一步的渗透操作",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.900Z"),
        "createTime": ISODate("2023-01-12T09:26:06.900Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc7"),
        "name": "系统弱口令",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf92",
        "riskDesc": "攻击者可以直接登录系统进行敏感操作",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.900Z"),
        "createTime": ISODate("2023-01-12T09:26:06.900Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc8"),
        "name": "DOS",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf92",
        "advice": "服务器迁高防",
        "riskDesc": "直接造成他人无法正常访问服务器，带来资金或名誉损失",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.900Z"),
        "createTime": ISODate("2023-01-12T09:26:06.900Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dc9"),
        "name": "疑似入侵",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf92",
        "advice": "对服务器进行排查",
        "riskDesc": "攻击者网站挂马或者网页存在非正常页面，存在入侵的可能性",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.900Z"),
        "createTime": ISODate("2023-01-12T09:26:06.900Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dca"),
        "name": "其他",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf92",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.900Z"),
        "createTime": ISODate("2023-01-12T09:26:06.900Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416ddb"),
        "name": "移动客户端",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416ddc"),
        "name": "本地代码执行",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416ddd"),
        "name": "组件拒绝服务漏洞",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416dde"),
        "name": "接口越权",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416ddf"),
        "name": "本地文件权限设置不当",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416de0"),
        "name": "本地敏感数据明文存储",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "advice": "（1）敏感数据加密存储\n（2）设置不可访问权限\n（3）禁止存储本地",
        "riskDesc": "敏感数据明文存储在用户本地，存在数据泄露风险",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416de1"),
        "name": "敏感数据明文传输",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "advice": "敏感数据禁止使用明文传输",
        "riskDesc": "敏感信息使用明文传输，存在数据泄露风险",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416de2"),
        "name": "敏感信息泄露",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    },
    {
        "_id": ObjectId("63bfd22e69b35a192a416de5"),
        "name": "其他",
        "sortNo": 0.0,
        "pid": "63bfd0c069b35a18580fbf95",
        "deleted": false,
        "createBy": "5db002504da8ad2e24d0052d",
        "updateBy": "5db002504da8ad2e24d0052d",
        "updateTime": ISODate("2023-01-12T09:26:06.901Z"),
        "createTime": ISODate("2023-01-12T09:26:06.901Z")
    }
]);


db.System_Menu.insert([
    {
        "_id": ObjectId("62c6825d69b35a24ca5daf17"),
        "name": "project-craw",
        "path": "/project/craw",
        "component": "craw/CrawList",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61962ed369b35a59d80ae828",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "CrawList",
            "title": "爬虫记录",
            "icon": "global"
        },
        "sortNo": 3.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-02-06T10:46:34.834Z"),
        "createTime": ISODate("2022-07-07T06:51:09.478Z")
    },
    {
        "_id": ObjectId("61cac0f269b35af657bb5022"),
        "name": "plugin-list",
        "path": "/plugin/list",
        "component": "plugin/Plugin",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "6197699cb3d4b440127f3262",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Plugin",
            "title": "插件列表",
            "icon": "appstore"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:40:09.232Z"),
        "createTime": ISODate("2021-12-28T07:46:58.128Z")
    },
    {
        "_id": ObjectId("623ad57069b35ad9d6246a87"),
        "name": "scan-cookie",
        "path": "/scan/cookie",
        "component": "engine/Cookie",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61976a0969b35a21518441cf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Cookie",
            "title": "全局cookie配置",
            "icon": "qrcode"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-03-23T08:08:16.355Z"),
        "createTime": ISODate("2022-03-23T08:08:16.355Z")
    },
    {
        "_id": ObjectId("60a46dbed70cf4217af30d30"),
        "name": "isystem-newPermissionList",
        "path": "/isystem/newPermissionList",
        "component": "system/NewPermissionList",
        "route": "1",
        "redirect": "",
        "parentId": "5e3be2af4da8ad2e24fc6fda",
        "meta": {
            "keepAlive": true,
            "internalOrExternal": false,
            "icon": "setting",
            "componentName": "NewPermissionList",
            "title": "菜单管理"
        },
        "sortNo": 2,
        "menuType": 1,
        "updateTime": ISODate("2020-06-27T09:16:40.442Z"),
        "createTime": ISODate("2020-02-06T09:55:59.269Z")
    },
    {
        "_id": ObjectId("62bbf44a69b35a8445107dde"),
        "name": "project-templates",
        "path": "/project/templates",
        "component": "project/Templates",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61962ed369b35a59d80ae828",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Templates",
            "title": "扫描模版",
            "icon": "credit-card"
        },
        "sortNo": 2.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:44:55.628Z"),
        "createTime": ISODate("2022-06-29T06:42:18.272Z")
    },
    {
        "_id": ObjectId("60a46e07d70cf4217af30e41"),
        "name": "isystem-roleUserList",
        "path": "/isystem/roleUserList",
        "component": "system/RoleUserList",
        "route": "1",
        "redirect": "",
        "parentId": "5e3be2af4da8ad2e24fc6fda",
        "meta": {
            "keepAlive": true,
            "internalOrExternal": false,
            "icon": "setting",
            "componentName": "RoleUserList",
            "title": "角色管理"
        },
        "sortNo": 2,
        "menuType": 1,
        "updateTime": ISODate("2020-06-27T09:16:40.442Z"),
        "createTime": ISODate("2020-02-06T09:55:59.269Z")
    },
    {
        "_id": ObjectId("62c68e5d69b35a7c85ea7ee0"),
        "name": "asset-url",
        "path": "/asset/url",
        "component": "asset/AssetUrl",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "62c68e0c69b35a7c85ea7edf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "AssetUrl",
            "title": "url资产",
            "icon": "link"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:34:34.836Z"),
        "createTime": ISODate("2022-07-07T07:42:21.288Z")
    },
    {
        "_id": ObjectId("6197699cb3d4b440127f3262"),
        "name": "plugin",
        "path": "/plugin",
        "component": "layouts/RouteView",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "/plugin/list",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "插件管理",
            "icon": "file-ppt"
        },
        "sortNo": 1.5,
        "menuType": 0,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-12-28T11:16:40.585Z"),
        "createTime": ISODate("2021-11-19T09:08:44.211Z")
    },
    {
        "_id": ObjectId("62c68e0c69b35a7c85ea7edf"),
        "name": "asset",
        "path": "/asset",
        "component": "layouts/RouteView",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "资产管理",
            "icon": "radar-chart"
        },
        "sortNo": 2.0,
        "menuType": 0,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-07-07T07:41:44.628Z"),
        "createTime": ISODate("2022-07-07T07:41:00.546Z")
    },
    {
        "_id": ObjectId("60acaed9d30a993cc15a2e78"),
        "name": "agent-list",
        "path": "/agent/list",
        "component": "agent/AgentList",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "60acaeb3d30a993cc15a2e77",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "AgentList",
            "title": "节点列表",
            "icon": "rocket"
        },
        "sortNo": 1.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-11-18T10:47:59.527Z"),
        "createTime": ISODate("2021-05-25T08:01:29.490Z")
    },
    {
        "_id": ObjectId("60a47030d70cf4217af3181b"),
        "name": "dashboard-analysis",
        "path": "/dashboard/analysis",
        "component": "dashboard/Analysis",
        "route": false,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Analysis",
            "title": "首页",
            "icon": "home"
        },
        "sortNo": 0.0,
        "menuType": 0,
        "updateTime": ISODate("2023-02-13T06:10:48.302Z"),
        "createTime": ISODate("2020-02-06T09:55:59.269Z"),
        "alwaysShow": false,
        "hidden": false,
        "perms": "",
        "permsStatus": 0,
        "permsType": 0
    },
    {
        "_id": ObjectId("61962ed369b35a59d80ae828"),
        "name": "project",
        "path": "/project",
        "component": "layouts/RouteView",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "项目管理",
            "icon": "project"
        },
        "sortNo": 1.0,
        "menuType": 0,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:43:53.170Z"),
        "createTime": ISODate("2021-11-18T10:45:39.353Z")
    },
    {
        "_id": ObjectId("619b69aa69b35a5b65c8e3a8"),
        "name": "scan-config",
        "path": "/scan/config",
        "component": "engine/Config",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61976a0969b35a21518441cf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Config",
            "title": "全局配置",
            "icon": "setting"
        },
        "sortNo": 1.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-11-22T09:58:19.978Z"),
        "createTime": ISODate("2021-11-22T09:58:02.842Z")
    },
    {
        "_id": ObjectId("6227138069b35aa61a5c161d"),
        "name": "agent-log",
        "path": "/agent/log",
        "component": "agent/LogList",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "60acaeb3d30a993cc15a2e77",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "LogList",
            "title": "节点日志",
            "icon": "file-text"
        },
        "sortNo": 3.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-03-08T08:28:56.016Z"),
        "createTime": ISODate("2022-03-08T08:27:44.815Z")
    },
    {
        "_id": ObjectId("61962f2169b35a59d80ae829"),
        "name": "project-list",
        "path": "/project/list",
        "component": "project/Project",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61962ed369b35a59d80ae828",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Project",
            "title": "项目列表",
            "icon": "bars"
        },
        "sortNo": 1.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-11-18T10:47:14.418Z"),
        "createTime": ISODate("2021-11-18T10:46:57.694Z")
    },
    {
        "_id": ObjectId("61cabfc769b35af657bb5020"),
        "name": "plugin-history",
        "path": "/plugin/history",
        "component": "plugin/History",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "6197699cb3d4b440127f3262",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "History",
            "title": "历史测试",
            "icon": "clock-circle"
        },
        "sortNo": 1.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:39:11.861Z"),
        "createTime": ISODate("2021-12-28T07:41:59.365Z")
    },
    {
        "_id": ObjectId("60a8c40e8ec8a87c0d315d6a"),
        "path": "",
        "component": "",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "60a46d43d70cf4217af30b3a",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "",
            "title": "用户性别",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 2,
        "perms": "user:sex",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-05-22T10:56:17.803Z"),
        "createTime": ISODate("2021-05-22T08:42:54.918Z"),
        "name": "user:sex",
        "ruleFlag": 0
    },
    {
        "_id": ObjectId("61976a0969b35a21518441cf"),
        "name": "scan",
        "path": "/scan",
        "component": "layouts/RouteView",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "扫描配置",
            "icon": "setting"
        },
        "sortNo": 3.0,
        "menuType": 0,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-07-07T07:41:36.442Z"),
        "createTime": ISODate("2021-11-19T09:10:33.885Z")
    },
    {
        "_id": ObjectId("6268f0aa69b35aaa07cdd6d6"),
        "name": "plugin-payload",
        "path": "/plugin/payload",
        "component": "plugin/Payload",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "6197699cb3d4b440127f3262",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Payload",
            "title": "字典管理",
            "icon": "file-text"
        },
        "sortNo": 2.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-02-07T07:40:41.945Z"),
        "createTime": ISODate("2022-04-27T07:28:42.438Z")
    },
    {
        "_id": ObjectId("61dd4f0a1dba2500092f6045"),
        "name": "vul-list",
        "path": "/vul/list",
        "component": "vul/List",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61dd4ea11dba2500092f6044",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "List",
            "title": "漏洞列表",
            "icon": "bars"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:41:52.653Z"),
        "createTime": ISODate("2022-01-11T09:34:02.087Z")
    },
    {
        "_id": ObjectId("5e3be2af4da8ad2e24fc6fda"),
        "name": "isystem",
        "path": "/isystem",
        "component": "layouts/RouteView",
        "route": true,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "系统管理",
            "icon": "setting"
        },
        "sortNo": 5.0,
        "menuType": 0,
        "updateTime": ISODate("2021-05-24T06:35:11.111Z"),
        "createTime": ISODate("2020-02-06T09:55:59.269Z"),
        "alwaysShow": false,
        "hidden": false,
        "perms": "",
        "permsStatus": 0,
        "permsType": 0
    },
    {
        "_id": ObjectId("60a878098ec8a8732b4bf1dc"),
        "path": "",
        "component": "",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "60a46d43d70cf4217af30b3a",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": ".",
            "title": "添加用户",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 2,
        "perms": "user:add",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-05-22T12:14:39.981Z"),
        "createTime": ISODate("2021-05-22T03:18:33.536Z"),
        "method": "POST",
        "name": "user:add"
    },
    {
        "_id": ObjectId("60acaf0cd30a993cc15a2e79"),
        "name": "agent-info-@ip",
        "path": "/agent/info/:ip",
        "component": "agent/AgentInfo",
        "route": true,
        "hidden": true,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "60acaeb3d30a993cc15a2e77",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "AgentInfo",
            "title": "节点详情",
            "icon": "file-text"
        },
        "sortNo": 2.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-07-07T06:48:35.617Z"),
        "createTime": ISODate("2021-05-25T08:02:20.193Z")
    },
    {
        "_id": ObjectId("61dd4ea11dba2500092f6044"),
        "name": "vul",
        "path": "/vul",
        "component": "layouts/RouteView",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "漏洞管理",
            "icon": "safety-certificate"
        },
        "sortNo": 1.0,
        "menuType": 0,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-01-11T09:36:35.811Z"),
        "createTime": ISODate("2022-01-11T09:32:17.119Z")
    },
    {
        "_id": ObjectId("630d7c8269b35a58646978b4"),
        "name": "isystem-sms-Template",
        "path": "isystem/sms/Template",
        "component": "message/SysMessageTemplateList",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "5e3be2af4da8ad2e24fc6fda",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "SysMessageTemplateList",
            "title": "通知管理",
            "icon": "message"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:32:47.216Z"),
        "createTime": ISODate("2022-08-30T02:57:06.881Z")
    },
    {
        "_id": ObjectId("60acaeb3d30a993cc15a2e77"),
        "name": "agent",
        "path": "/agent",
        "component": "layouts/RouteView",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "RouteView",
            "title": "节点管理",
            "icon": "hdd"
        },
        "sortNo": 4.0,
        "menuType": 0,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-07-07T07:41:28.963Z"),
        "createTime": ISODate("2021-05-25T08:00:51.188Z")
    },
    {
        "_id": ObjectId("6346730869b35a701887a976"),
        "name": "plugin-source",
        "path": "/plugin/source",
        "component": "plugin/SourcePlugin",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "6197699cb3d4b440127f3262",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "SourcePlugin",
            "title": "开源插件",
            "icon": "appstore"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-01-11T07:38:14.560Z"),
        "createTime": ISODate("2022-10-12T07:55:52.344Z")
    },
    {
        "_id": ObjectId("62b2877669b35ac6161498e4"),
        "name": "engine-limit",
        "path": "/engine/limit",
        "component": "engine/Limit",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61976a0969b35a21518441cf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Limit",
            "title": "域名配置",
            "icon": "global"
        },
        "sortNo": 3.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-06-22T03:07:46.560Z"),
        "createTime": ISODate("2022-06-22T03:07:34.280Z")
    },
    {
        "_id": ObjectId("61a7624369b35ade823ee7a1"),
        "name": "project-detail-@id",
        "path": "/project/detail/:id",
        "component": "project/ProjectDetail",
        "route": true,
        "hidden": true,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61962ed369b35a59d80ae828",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "ProjectDetail",
            "title": "项目详情",
            "icon": ""
        },
        "sortNo": 2.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-12-01T11:53:48.319Z"),
        "createTime": ISODate("2021-12-01T11:53:39.416Z")
    },
    {
        "_id": ObjectId("60a46d43d70cf4217af30b3a"),
        "name": "isystem-user",
        "path": "/isystem/user",
        "component": "system/UserList",
        "route": "1",
        "redirect": "",
        "parentId": "5e3be2af4da8ad2e24fc6fda",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "icon": "setting",
            "componentName": "UserList",
            "title": "用户管理"
        },
        "sortNo": 2,
        "menuType": 1,
        "updateTime": ISODate("2020-06-27T09:16:40.442Z"),
        "createTime": ISODate("2020-02-06T09:55:59.269Z"),
        "ruleFlag": 1
    },
    {
        "_id": ObjectId("637ca23269b35ad54a7d73d4"),
        "name": "asset-domain",
        "path": "/asset/domain",
        "component": "asset/Domain",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "62c68e0c69b35a7c85ea7edf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Domain",
            "title": "域名资产",
            "icon": "dribbble"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-11-22T10:21:05.744Z"),
        "createTime": ISODate("2022-11-22T10:19:30.771Z")
    },
    {
        "_id": ObjectId("637ca28869b35ad54a7d73d5"),
        "name": "asset-ip",
        "path": "/asset/ip",
        "component": "asset/Ip",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "62c68e0c69b35a7c85ea7edf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Ip",
            "title": "IP资产",
            "icon": "laptop"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-02-07T08:00:58.264Z"),
        "createTime": ISODate("2022-11-22T10:20:56.234Z")
    },
    {
        "_id": ObjectId("637dd80669b35a82881559f2"),
        "name": "asset-ip-info-@ip",
        "path": "/asset/ip/info/:ip",
        "component": "asset/IpDetail",
        "route": true,
        "hidden": true,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "62c68e0c69b35a7c85ea7edf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "IpDetail",
            "title": "IP资产详情",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-02-07T08:01:06.560Z"),
        "createTime": ISODate("2022-11-23T08:21:26.083Z")
    },
    {
        "_id": ObjectId("63875e7069b35a724f90158c"),
        "name": "vul:handle",
        "path": "",
        "component": "",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61dd4f0a1dba2500092f6045",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "",
            "title": "处理权限",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 2,
        "perms": "vul:handle",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-11-30T13:45:20.814Z"),
        "createTime": ISODate("2022-11-30T13:45:20.814Z")
    },
    {
        "_id": ObjectId("6387628d69b35a724f90158d"),
        "name": "plugin:show",
        "path": "",
        "component": "",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61dd4f0a1dba2500092f6045",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "",
            "title": "插件详情",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 2,
        "perms": "plugin:show",
        "permsType": 0,
        "permsStatus": 1,
        "updateTime": ISODate("2022-12-01T07:08:42.212Z"),
        "createTime": ISODate("2022-11-30T14:02:53.591Z")
    },
    {
        "_id": ObjectId("6390342269b35a0ae3cae251"),
        "name": "isystem-config",
        "path": "/isystem/config",
        "component": "system/Config",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "5e3be2af4da8ad2e24fc6fda",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Config",
            "title": "通知配置",
            "icon": "setting"
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-02-08T01:59:21.859Z"),
        "createTime": ISODate("2022-12-07T06:35:14.549Z")
    },
    {
        "_id": ObjectId("61976a4569b35a21518441d0"),
        "name": "scan-whitelist",
        "path": "/scan/whitelist",
        "component": "engine/WhiteList",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61976a0969b35a21518441cf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "WhiteList",
            "title": "全局白名单配置",
            "icon": "file"
        },
        "sortNo": 2.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-06-22T03:07:58.361Z"),
        "createTime": ISODate("2021-11-19T09:11:33.970Z")
    },
    {
        "_id": ObjectId("6393075669b35ab493ce8a12"),
        "name": "scan-vul-cate",
        "path": "/scan/vul/cate",
        "component": "vul/Category",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "61dd4ea11dba2500092f6044",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "Category",
            "title": "漏洞类型",
            "icon": "table"
        },
        "sortNo": 3.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2023-02-15T08:10:54.638Z"),
        "createTime": ISODate("2022-12-09T10:00:54.967Z")
    },
    {
        "_id": ObjectId("60a8f5f78ec8a88185cc4c58"),
        "path": "",
        "component": "",
        "route": true,
        "hidden": false,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "60a46d43d70cf4217af30b3a",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "",
            "title": "编辑用户",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 2,
        "perms": "user:edit",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2021-05-22T12:15:51.295Z"),
        "createTime": ISODate("2021-05-22T12:15:51.295Z")
    },
    {
        "_id": ObjectId("637df3c469b35a0beb871dc0"),
        "name": "asset-domain-info-@domain",
        "path": "/asset/domain/info/:domain",
        "component": "asset/DomainDetail",
        "route": true,
        "hidden": true,
        "alwaysShow": false,
        "redirect": "",
        "parentId": "62c68e0c69b35a7c85ea7edf",
        "meta": {
            "keepAlive": false,
            "internalOrExternal": false,
            "componentName": "DomainDetail",
            "title": "域名资产详情",
            "icon": ""
        },
        "sortNo": 0.0,
        "menuType": 1,
        "perms": "",
        "permsType": 1,
        "permsStatus": 1,
        "updateTime": ISODate("2022-11-23T10:19:48.021Z"),
        "createTime": ISODate("2022-11-23T10:19:48.021Z")
    }
]);


db.System_RoleMenu.insert([
    {
        "_id": ObjectId("639ab90dc9a9568d4a172216"),
        "dataPermsIds": [],
        "menuId": "62bbf44a69b35a8445107dde",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172217"),
        "dataPermsIds": [],
        "menuId": "637ca28869b35ad54a7d73d5",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172219"),
        "dataPermsIds": [],
        "menuId": "6387628d69b35a724f90158d",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17221a"),
        "dataPermsIds": [],
        "menuId": "630d7c8269b35a58646978b4",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17221b"),
        "dataPermsIds": [],
        "menuId": "60a8f5f78ec8a88185cc4c58",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17221c"),
        "dataPermsIds": [],
        "menuId": "6197699cb3d4b440127f3262",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17221d"),
        "dataPermsIds": [],
        "menuId": "623ad57069b35ad9d6246a87",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17221e"),
        "dataPermsIds": [],
        "menuId": "61a7624369b35ade823ee7a1",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17221f"),
        "dataPermsIds": [],
        "menuId": "61962f2169b35a59d80ae829",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172220"),
        "dataPermsIds": [],
        "menuId": "62c6825d69b35a24ca5daf17",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172221"),
        "dataPermsIds": [],
        "menuId": "61976a0969b35a21518441cf",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172222"),
        "dataPermsIds": [],
        "menuId": "60a46d43d70cf4217af30b3a",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172223"),
        "dataPermsIds": [],
        "menuId": "61dd4ea11dba2500092f6044",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172226"),
        "dataPermsIds": [],
        "menuId": "61976a4569b35a21518441d0",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172227"),
        "dataPermsIds": [],
        "menuId": "6227138069b35aa61a5c161d",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172228"),
        "dataPermsIds": [],
        "menuId": "60a878098ec8a8732b4bf1dc",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172229"),
        "dataPermsIds": [],
        "menuId": "6346730869b35a701887a976",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17222a"),
        "dataPermsIds": [],
        "menuId": "60a47030d70cf4217af3181b",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17222c"),
        "dataPermsIds": [],
        "menuId": "619b69aa69b35a5b65c8e3a8",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17222e"),
        "dataPermsIds": [],
        "menuId": "61962ed369b35a59d80ae828",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17222f"),
        "dataPermsIds": [],
        "menuId": "61dd4f0a1dba2500092f6045",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172230"),
        "dataPermsIds": [],
        "menuId": "60a8c40e8ec8a87c0d315d6a",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172231"),
        "dataPermsIds": [],
        "menuId": "61cabfc769b35af657bb5020",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172232"),
        "dataPermsIds": [],
        "menuId": "637df3c469b35a0beb871dc0",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172233"),
        "dataPermsIds": [],
        "menuId": "62b2877669b35ac6161498e4",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172234"),
        "dataPermsIds": [],
        "menuId": "637ca23269b35ad54a7d73d4",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172235"),
        "dataPermsIds": [],
        "menuId": "5e3be2af4da8ad2e24fc6fda",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172236"),
        "dataPermsIds": [],
        "menuId": "6268f0aa69b35aaa07cdd6d6",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172237"),
        "dataPermsIds": [],
        "menuId": "637dd80669b35a82881559f2",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172238"),
        "dataPermsIds": [],
        "menuId": "60acaed9d30a993cc15a2e78",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17223a"),
        "dataPermsIds": [],
        "menuId": "61cac0f269b35af657bb5022",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17223b"),
        "dataPermsIds": [],
        "menuId": "62c68e5d69b35a7c85ea7ee0",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17223c"),
        "dataPermsIds": [],
        "menuId": "6390342269b35a0ae3cae251",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17223e"),
        "dataPermsIds": [],
        "menuId": "60acaeb3d30a993cc15a2e77",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a17223f"),
        "dataPermsIds": [],
        "menuId": "60a46e07d70cf4217af30e41",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172240"),
        "dataPermsIds": [],
        "menuId": "60acaf0cd30a993cc15a2e79",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172241"),
        "dataPermsIds": [],
        "menuId": "60a46dbed70cf4217af30d30",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172242"),
        "dataPermsIds": [],
        "menuId": "63875e7069b35a724f90158c",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172243"),
        "dataPermsIds": [],
        "menuId": "62c68e0c69b35a7c85ea7edf",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    },
    {
        "_id": ObjectId("639ab90dc9a9568d4a172244"),
        "dataPermsIds": [],
        "menuId": "6393075669b35ab493ce8a12",
        "roleId": "5e36ddf74da8ad2e24fb5f51"
    }
]);
