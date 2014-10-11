lua_php_md5crypt
================

~~基于openresty实现的模拟php的md5 crypt module~~

~~配合openresty使用，需要luajit支持，引用了luajit的bit库。~~
~~如果有其它md5的方法，替换掉crypt.lua里的 local md5 = ngx.md5，就可以直接用luajit执行了。~~

指前的方面存在bug，用ffi重写
