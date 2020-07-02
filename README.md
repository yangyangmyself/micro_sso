#单点登录升级改，单点登录采用Oauth2，推荐以code获取token

#改造要求：

1）支持普通用户登录/证书登录

2）OAuth2 code自定义管理，目前采用存取redis，用于集群跨节点生成token

3）Token 可以自定义，添加额外属性，如支持kong

4）后端接口支持以json及页面跳转方式返回code

5）前端密码传递后端采用RSA加密传
