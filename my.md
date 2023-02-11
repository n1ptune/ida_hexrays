There are 20 examples in /ida_path/plugins/hexrays_sdk/plugins, you can learn from that, you can also see it at [https://hex-rays.com/products/decompiler/manual/sdk/examples.shtml](https://hex-rays.com/products/decompiler/manual/sdk/examples.shtml).They are all written in cpp.
##get starts
there are some background information at [https://hex-rays.com/blog/hex-rays-decompiler-primer/](https://hex-rays.com/blog/hex-rays-decompiler-primer/) and [Hex-Rays SDK document](https://hex-rays.com/products/decompiler/manual/sdk/index.shtml).
Here is a template written in python. All you need to do is just edit func visit_expr or visit_insn or both.
```
import idaapi
import idc

class Handler(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
    
    #callback when visit every statement
    def visit_expr(self, expr:idaapi.cexpr_t) -> "int":
        return 0
    #callback when visit every expression
    def visit_insn(self, ins:idaapi.idaapi.cinsn_t) -> "int":
        return 0

def main():
    func = idaapi.get_func(idc.here())  # get current func
    cfunc = idaapi.decompile(func.start_ea)  # decompile func
    handler = Handler(cfunc)
    handler .apply_to(cfunc.body, None)

if __name__ == '__main__':
    main()
```
note: if you want to handle the whole func, the return value of visit_expr and visit_insn must be zero or it will stop when you return 1.

##Pratice
Get every xref of a func and print its args
Here is the code
```
import idaapi
import idc

class Handler(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
    def visit_expr(self, expr: idaapi.cexpr_t  ) -> "int":
        #only handle every call expr
        if expr.op != idaapi.cot_call:
            return 0
        #get callee func name 
        func_name = idaapi.get_func_name(expr.x.obj_ea)
        if( func_name == "target_funcname"):
            #get caller func name
            caller_name = idaapi.get_func_name(expr.ea)
            out_str = f"{caller_name} call {func_name}("

            #get arglist length
            args = expr.a.size()
            for i in range(args):
                #get every arg
                arg = expr.a[i]
                if arg.op == idaapi.cot_num:     #case arg type direct value
                    out_str += str(arg.n._value)
                elif arg.op == idaapi.cot_obj:   #case arg type string
                    if ida_bytes.get_strlit_contents(arg.obj_ea, -1, 0) == None:
                        continue
                    out_str += "\""
                    out_str += ida_bytes.get_strlit_contents(arg.obj_ea, -1, 0).decode().replace("\n", "\\n")
                    out_str += "\""
                else:
                    out_str += f"a{i+1}"
                out_str += ", " if i < args - 1 else ")" 
            print(out_str)
            
        return 0
def main():
    for func_addr in Functions():
        #only handle the func in .text segment
        if idc.get_segm_name(func_addr) != ".text":
            continue
        func = idaapi.decompile(func_addr)
        handler = Handler(func)
        handler.apply_to(func.body, None)
if __name__ == "__main__":
    main()
```
If you want to do more pratice , you can rewrite the examples in python.