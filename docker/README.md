# NextScan黑盒扫描器

## 简介

黑盒扫描器

+ web （admin）黑盒扫描器管理服务
+ scan 黑盒扫描器扫描服务
+ craw 黑盒扫描器爬虫服务



### 启动与停止
当前文件夹下
```shell
docker-compose up #启动
docker-compose stop #停止
```

### 访问
```
http://你的ip:8080

用户名：admin
默认密码：123456
```
### 自定义配置

#### 修改docker-compose.yaml配置项
+ 修改redis密码
```yaml
# 默认密码：3d7a6447328dcde6
redis:
  command:
    --requirepass "你的密码"
```
+ 修改mongo数据库密码
```yaml
mongo:
    environment:
      ### admin 身份验证数据库用户名及密码
      MONGO_INITDB_ROOT_USERNAME: admin数据库用户名
      MONGO_INITDB_ROOT_PASSWORD: admin数据库密码
      ### NextScan数据库用户名
      MONGO_USERNAME: 你的用户名
      # NextScan数据库密码
      MONGO_PASSWORD: 你的密码

```

+ 修改etcd密码
```yaml
etcd:
    environment:
      # etcd root用户密码
      - ETCD_ROOT_PASSWORD=你的密码
```

+ 修改扫描服务对应配置
```yaml
scan:
    command:
      #extranet(外网环境）intranet（内网环境）
      --group=extranet
      #管理服务器地址
      --server=http://ns-admin:8080
```
+ 修改爬虫服务对应配置
```yaml
craw:
    command:
      #extranet(外网环境）intranet（内网环境）
      --group=extranet
      #管理服务器地址
      --server=http://ns-admin:8080
```
#### 修改对应conf.ini配置
+ 详情见conf.ini文件
