# 项目功能
实现一个mini版的网络pcap文件的解析库，熟悉API的设计思想（需要先熟悉pcap文件格式）
- API的设计
- so库的封装
- 单元测试覆盖

# 设计思想
####  将实现与接口分开，将私有的实现部分隐藏，
- 1）. 使程序员不能轻易地访问实现部分，但可以看到对应的方法；
- 2）. 如果后期任何方法的实现细节做迭代，接口完全兼容，没有人会因此而受到影响；
- 3）. 面向对象是一种思想而不是一种语言，本文档使用使用C语言编写。

# 编译&运行

- 环境：gcc 4.8.5

- 编译：
  ```
    make
    sh run.sh
  ```  
- 运行：
  ```
    ./a.out 1.pcap '(protocol=tcp)' | grep -v 'Not support dstport'
    ./a.out 1.pcap '(&(dstport=80)(dstip=203.208.37.99))'
 ```
