本程序功能不齐全，建议搭配其他工具包使用，代码可以使用小熊猫c++直接编译，By Hyrvex。


bin文件夹中存放了可以直接运行的程序文件，其中：

StudentMain.exe是标准版，可以解锁网络、U盘和部分系统设置，以及结束机房管理助手的相关进程

fastversion.exe是前者的保底版，可以快速运行，但不稳定

student.exe是用于单独解锁网络、U盘和部分系统设置的程序。

前两者程序最好不要在Windows 7系统上直接运行！


注意事项：
如果外部exe程序被禁止，你可以直接使用小熊猫c++(Dev-C++)自己编译运行。
你也可以运行bin文件夹中提供的程序(StudentMain.exe和fastversion.exe，后者执行速度快，但有概率蓝屏)，如果放入U盘不能直接运行，你可以尝试将同目录的StudentTool.iso文件拷入U盘，双击该文件，在文件资源管理器的虚拟光驱中找到程序并运行。


重要事项：
目前仅支持Windows 10及以上系统直接运行。
Windows 7系统可以尝试在资源管理器的地址栏输入{taskkill /f /fi "USERNAME eq %username%"}(不要把大括号{}也输入进去了)，
随后按下ctrl+shift+esc或ctrl+alt+del打开任务管理器，运行"explorer.exe"，
随后打开资源管理器窗口，在资源管理器的地址栏输入"services.msc"，回车确定，
在弹出的服务窗口中往下滑找到"zmserv"，将其安全停止，
随后可以运行student.exe，恢复系统功能
(恢复其他功能后，如果桌面没有自动出现，还需要按下ctrl+shift+esc或ctrl+alt+del打开任务管理器，运行"explorer.exe")
