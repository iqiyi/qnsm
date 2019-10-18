# Contributing过程
## fork代码 

    从 https://github.com/iqiyi/qnsm fork代码到你的github的个人账号
    你的代码现在位于 https://github.com/xxx/qnsm (xxx改为你的github账号)

## 本地clone代码
```bash
git clone https://github.com/xxx/qnsm.git
cd qnsm
```

## 创建名字为 upstream 的上游地址
```bash
       $ git remote add upstream https://github.com/iqiyi/qnsm.git

       $ git remote -v

       origin  https://github.com/xxx/qnsm.git (fetch)
       origin  https://github.com/xxx/qnsm.git (push)
       upstream        https://github.com/iqiyi/qnsm.git (fetch)
       upstream        https://github.com/iqiyi/qnsm.git (push)
```

## 同步上游代码 
```bash
$ git fetch upstream
$ git checkout master
$ git merge upstream/master
```

## 选择工作分支

除了处理紧急bug，一般选择devel开发分支
```bash
$ git checkout devel
error: pathspec 'devel' did not match any file(s) known to git.
```

如果遇到以上报错，
```bash
$ git checkout -b devel
Switched to a new branch 'devel'
$ git branch --set-upstream-to=origin/devel devel
Branch devel set up to track remote branch devel from origin.
$ git pull 
$ git pull upstream devel
```

## 创建自己的分支

功能开发请用feature-xxx, bugfix请用 hotfix-xxx，这里以contribute文档为例。
```bash
$ git checkout -b feature-contribute-doc devel
Switched to a new branch 'feature-contribute-doc'
```

代码开发，修改工程, 本地提交commits
```bash
$ git add CONTRIBUTING.md
$ git commit -m "update contribute doc"
```

在 push 本地代码之前，检查feature-xxx分支是否部分落后于上游（upstream） devel 分支
```bash
$ git checkout devel
$ git pull upstream devel 
$ git log feature-contribute-doc..devel
```

使用rebase合并代码
```bash
$ git checkout feature-contribute-doc
$ git rebase devel
```

提交到远端
```bash
$ git push origin feature-contribute-doc
```

## 发起PR

这部分直接在github上操作。

提交PR后，等待评审人员的review，会给出相关反馈，contributor和评审人员有可能会有好几次交流。

如果被接受的话，项目管理人员负责合并代码至devel分支。


PR被关闭后，删除分支
```bash
$ git branch -D feature-contribute-doc
$ git push origin --delete feature-contribute-doc
```