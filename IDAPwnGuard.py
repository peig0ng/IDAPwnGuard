import idaapi
import idautils
import idc
import ida_funcs
import ida_nalt
import ida_lines
import ida_idaapi
import ida_bytes

class PwnScanner(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "自动化 PWN 漏洞扫描工具（增强版）"
    help = "高级二进制漏洞检测与报告生成系统"
    wanted_name = "PWN 漏洞扫描器+"
    wanted_hotkey = "Ctrl-Shift-V"

    # 漏洞风险颜色配置（颜色值为背景色）
    COLOR_CONFIG = {
        'HIGH_RISK': 0x2020C0,   # 红色
        'MEDIUM_RISK': 0x4040FF, # 蓝色
        'HEAP_RISK': 0x00C0C0,   # 青色
        'INT_OVERFLOW': 0xC0C000 # 黄色
    }

    def init(self):
        self.init_risk_functions()
        self.report = []  # 存储扫描结果
        idaapi.msg("[+] PWN 漏洞扫描器+ 加载成功\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.scan_all_vulnerabilities()
        self.generate_report()

    def term(self):
        idaapi.msg("[+] PWN 漏洞扫描器+ 退出\n")

    def init_risk_functions(self):
        """初始化漏洞特征数据库"""
        self.risk_functions = {
            'strcpy': ('缓冲区溢出（无长度检查）', 'HIGH_RISK'),
            'strncpy': ('可能存在边界未校验风险', 'MEDIUM_RISK'),
            'gets': ('不受限制的输入（极其危险）', 'HIGH_RISK'),
            'strcat': ('可能发生缓冲区溢出', 'HIGH_RISK'),
            'sprintf': ('格式化字符串未检查', 'HIGH_RISK'),
            'printf': ('格式化字符串漏洞风险', 'HIGH_RISK'),
            'fprintf': ('格式化字符串漏洞风险', 'HIGH_RISK'),
            'snprintf': ('可能存在格式化字符串风险', 'MEDIUM_RISK'),
            'vsprintf': ('可变参数格式化风险', 'HIGH_RISK'),
            'malloc': ('堆内存分配——注意 UAF 风险', 'HEAP_RISK'),
            'calloc': ('堆内存分配带初始化——注意 UAF 风险', 'HEAP_RISK'),
            'free': ('释放堆内存——需检查 Double Free，UAF 风险', 'HEAP_RISK'),
            'realloc': ('堆重新分配风险', 'HEAP_RISK'),
            'atoi': ('整数转换风险（符号/类型问题）', 'INT_OVERFLOW'),
            'atol': ('整数转换风险（符号/类型问题）', 'INT_OVERFLOW'),
            'rand': ('伪随机数风险，建议使用更安全的 RNG', 'MEDIUM_RISK'),
            'srand': ('伪随机种子设定，注意可预测性', 'MEDIUM_RISK'),
            'system': ('命令注入风险', 'HIGH_RISK'),
            'popen': ('命令注入风险', 'HIGH_RISK'),
            'open': ('文件打开——注意路径遍历风险', 'MEDIUM_RISK'),
            'fopen': ('文件打开——注意模式和权限', 'MEDIUM_RISK'),
            'read': ('读取数据——注意缓冲区大小', 'MEDIUM_RISK'),
            'write': ('写入数据——注意溢出风险', 'MEDIUM_RISK'),
            'memcpy': ('内存复制操作——检查复制大小是否正确', 'MEDIUM_RISK'),
            'memset': ('内存初始化操作——检查初始化参数是否合法', 'MEDIUM_RISK')
        }

    def scan_all_vulnerabilities(self):
        idaapi.msg("[+] 开始全面漏洞扫描...\n")
        self.report.clear()
        self.scan_dangerous_functions()
        self.check_format_strings()
        self.analyze_heap_operations()
        self.check_integer_issues()
        self.check_system_calls()
        self.detect_cf_injection()
        idaapi.msg(f"[+] 漏洞扫描完成，共发现 {len(self.report)} 处风险。\n")

    def scan_dangerous_functions(self):
        for func_name, (desc, level) in self.risk_functions.items():
            addr = idc.get_name_ea_simple(func_name)
            if addr == idc.BADADDR: continue
            for xref in idautils.XrefsTo(addr):
                if idaapi.is_call_insn(xref.frm):
                    self.mark_vulnerability(xref.frm, desc, level)

    def check_format_strings(self):
        fmt_funcs = ['printf', 'sprintf', 'fprintf', 'snprintf', 'vsprintf']
        for f in fmt_funcs:
            addr = idc.get_name_ea_simple(f)
            if addr == idc.BADADDR: continue
            for xref in idautils.XrefsTo(addr):
                if self._is_format_string_vuln(xref.frm):
                    self.mark_vulnerability(xref.frm, '用户可控格式字符串风险', 'HIGH_RISK')

    def analyze_heap_operations(self):
        allocs = {}
        frees = {}
        for func in ['malloc', 'calloc', 'realloc', 'free']:
            addr = idc.get_name_ea_simple(func)
            if addr == idc.BADADDR: continue
            for xref in idautils.XrefsTo(addr):
                ea = xref.frm
                try:
                    if func in ('malloc', 'calloc'):
                        allocs[ea] = self.get_allocation_size(ea)
                    elif func == 'free':
                        ptr = self.get_free_pointer(ea)
                        frees.setdefault(ptr, []).append(ea)
                        if len(frees[ptr]) > 1:
                            self.mark_vulnerability(ea, '检测到可能双重释放', 'HEAP_RISK')
                except Exception as e:
                    idaapi.msg(f"[!] 堆分析错误 at {hex(ea)}: {e}\n")

    def check_integer_issues(self):
        for seg in idautils.Segments():
            for head in idautils.Heads(seg):
                if idaapi.is_code(idaapi.get_flags(head)):
                    insn = idautils.DecodeInstruction(head)
                    if insn and insn.itype in [idaapi.NN_mul, idaapi.NN_add, idaapi.NN_sub]:
                        if self.check_integer_overflow(insn):
                            self.mark_vulnerability(head, '整数运算溢出风险', 'INT_OVERFLOW')

    def check_system_calls(self):
        for call in ['execve', 'system', 'popen']:
            addr = idc.get_name_ea_simple(call)
            if addr == idc.BADADDR: continue
            for xref in idautils.XrefsTo(addr):
                if self._is_user_controlled(xref.frm, 0):
                    self.mark_vulnerability(xref.frm, f'用户控制的 {call} 调用', 'HIGH_RISK')

    def detect_cf_injection(self):
        """检测潜在控制流劫持（间接 jmp/call）"""
        for seg in idautils.Segments():
            for head in idautils.Heads(seg):
                if idaapi.is_code(idaapi.get_flags(head)):
                    insn = idautils.DecodeInstruction(head)
                    if insn and insn.itype in [idaapi.NN_jmp, idaapi.NN_call] and insn.Op1.type == idaapi.o_reg:
                        if self._track_user_input(insn.Op1.reg, head):
                            self.mark_vulnerability(head, '潜在控制流劫持', 'HIGH_RISK')

    def mark_vulnerability(self, ea, desc, level):
        color = self.COLOR_CONFIG.get(level, 0xFFFFFF)
        idc.set_color(ea, idc.CIC_ITEM, color)
        prev = idc.get_cmt(ea, 0) or ''
        cmt = f"[!] {level} 风险: {desc}"
        idc.set_cmt(ea, prev + '\n' + cmt, 0)
        self.report.append((ea, level, desc))
        idaapi.msg(f"[!] 在 {hex(ea)} 发现: {desc}\n")

    def generate_report(self):
        """在 IDA 输出窗口生成扫描报告"""
        text = "=== PWN 漏洞扫描报告 ===\n"
        for ea, level, desc in self.report:
            text += f"地址 {hex(ea)}: [{level}] {desc}\n"
        idaapi.msg(text)

    # ---------- 辅助函数 ----------
    def _is_format_string_vuln(self, call_ea):
        insn = idautils.DecodeInstruction(call_ea)
        if not insn: return False
        arg_offset = 1 if ida_nalt.get_abi_name() == 'ms' else 0
        if arg_offset >= len(insn.ops): return False
        op = insn.ops[arg_offset]
        if op.type == idaapi.o_imm:
            return idc.get_str_type(op.value) in [idc.STRTYPE_C, idc.STRTYPE_C_16]
        if op.type == idaapi.o_reg:
            return self._track_user_input(op.reg, call_ea)
        return False

    def _track_user_input(self, reg, ea):
        cur = ea
        for _ in range(50):
            cur = idc.prev_head(cur)
            insn = idautils.DecodeInstruction(cur)
            if not insn: continue
            if insn.itype == idaapi.NN_mov and insn.Op1.reg == reg:
                if insn.Op2.type == idaapi.o_displ:
                    return True
                if insn.Op2.type == idaapi.o_reg:
                    reg = insn.Op2.reg
        return False

    def _is_user_controlled(self, ea, op_idx):
        insn = idautils.DecodeInstruction(ea)
        if not insn or op_idx >= len(insn.ops): return False
        op = insn.ops[op_idx]
        if op.type == idaapi.o_imm: return False
        if op.type == idaapi.o_reg:
            return self._track_user_input(op.reg, ea)
        return False

    def get_allocation_size(self, ea):
        insn = idautils.DecodeInstruction(ea)
        if not insn or not insn.ops: return None
        op = insn.ops[0]
        return op.value if op.type == idaapi.o_imm else None

    def get_free_pointer(self, ea):
        insn = idautils.DecodeInstruction(ea)
        if not insn or not insn.ops: return None
        return insn.ops[0].reg if insn.ops[0].type == idaapi.o_reg else None

    def check_integer_overflow(self, insn):
        v1 = self.get_operand_value(insn.ea, 0)
        v2 = self.get_operand_value(insn.ea, 1)
        if v1 is None or v2 is None: return False
        if insn.itype == idaapi.NN_mul:
            return v1 * v2 > 0xFFFFFFFF
        if insn.itype == idaapi.NN_add:
            return v1 + v2 > 0xFFFFFFFF
        if insn.itype == idaapi.NN_sub:
            return v1 - v2 < 0
        return False

    def get_operand_value(self, ea, idx):
        insn = idautils.DecodeInstruction(ea)
        if not insn or idx >= len(insn.ops): return None
        op = insn.ops[idx]
        if op.type == idaapi.o_imm:
            return op.value
        if op.type == idaapi.o_reg:
            cur = ea
            for _ in range(20):
                cur = idc.prev_head(cur)
                pi = idautils.DecodeInstruction(cur)
                if pi and pi.itype == idaapi.NN_mov and pi.Op1.reg == op.reg and pi.Op2.type == idaapi.o_imm:
                    return pi.Op2.value
        return None


def PLUGIN_ENTRY():
    return PwnScanner()
