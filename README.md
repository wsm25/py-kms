# 历史
*py-kms* 是 [markedsword](http://forums.mydigitallife.info/members/183074-markedsword)编写的 *node-kms* 的一部分，由C#, C++,或是 .NET 的KMSEmulator实现，原作者是[CODYQX4](http://forums.mydigitallife.info/members/89933-CODYQX4) ，它源自微软官方KMS的反向工程代码。

# 特征
- 响应V4, V5, V6的KMS请求
- 支持激活 Windows 7/8/8.1/10/2008R2/2012/2012R2/2016 和 Office 2010/2013/2016/2019.
- 它由python编写而成

# 依赖
- 安装有`argparse`模块的Python 2.6+
- 如果安装了`pytz` 模块，详细输出信息中的“请求时间”会转换为本地时间；否则，会输出UTC时间。

# 食用方法
- 要启动server，请运行`python server.py [listen_address] [port]`。默认代理地址是`0.0.0.0`（所有网口），默认端口为`1688`。
- 要运行client，请运行`python client.py server_address [port]`。默认端口为`1688`