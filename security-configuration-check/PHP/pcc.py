import re
pcc_name = "PHP Secure Configuration Checker(Implemented by Python)"
pcc_version = "v1"
pcc_date = "2021-11-07"  #Time to start development
pcc_src_url = "https://github.com/sektioneins/pcc" # download URL
# test result codes
TEST_CRITICAL="critical" # critical problem found.
TEST_HIGH="high"         # high problem found.
TEST_MEDIUM="medium"     # medium. this may be a problem.
TEST_LOW="low"           # low. boring problem found.
TEST_MAYBE="maybe"       # potential security risk. please check manually.
TEST_COMMENT="comment"   # odd, but still worth mentioning.
TEST_OK="ok"             # everything is fine. move along.
TEST_SKIPPED="skipped"   # probably not applicable here.
TEST_UNKNOWN="unknown"   # something is unknown.
DIRECTORY_SEPARATOR='/'
#


PHP_MAJOR_VERSION=int() #PHP_MAJOR_VERSION #(int)当前 PHP 版本的主版本号，为整数形式（例如："5.2.7-extra" 版本是 int(5) ）
PHP_MINOR_VERSION=int() #(int)当前 PHP 版本的子版本号，为整数形式（例如："5.2.7-extra" 版本是 int(2) ）
E_ERROR=int()           #(int)致命的运行时错误。这类错误一般是不可恢复的情况，例如内存分配导致的问题。后果是导致脚本终止不再继续运行。
cfg = {
    'output_type':'text',
	'allowed_output_types':['text', 'html'],
    'showall': 0,
    'result_codes_default': [TEST_CRITICAL, TEST_HIGH, TEST_MEDIUM, TEST_LOW, TEST_MAYBE, TEST_COMMENT],
    'need_update' : 0
}

all_result_codes = [TEST_CRITICAL, TEST_HIGH, TEST_MEDIUM, TEST_LOW, TEST_MAYBE, TEST_COMMENT, TEST_OK, TEST_SKIPPED, TEST_UNKNOWN]

trbs={} #test result by severity, eg.trbs[TEST_OK][...]


def print_res(meta, result, reason = None, recommendation = None):
    res={"meta":meta,"result" :result, "reason" :reason, "recommendation":recommendation}
    print(res)


_SERVER={}
#intval — 获取变量的整数值
def intval(str)->int:
    value = re.search(r'\d+', str).group()
    return int(value)
#eg 1KM:str->1*1024:int
def ini_atol(str)->int:
    value=intval(str)
    if 'K' in str.upper():
        value*=1024
    elif 'M' in str.upper():
        value*=1024*1024
    elif 'G' in str.upper():
        value*=1024*1024*1024
    return value

#?????????????????????????????????
def ini_list(val):
    if val=="" or val==" " or val==None:
        return False
    return True
# return enable/unenable
def is_on(value)->bool:
    if value=='0' or value=='' or value.lower()=='off':
        return False
    return True

#parse helptext
def parse_helptext()->dict:
    helptext={}
    lines=open('helptext.txt').readlines()
    for line in lines:
        line=line.strip('\n')
        line=line.split('=>')
        key=line[0].strip(' ').strip("'")
        desc=line[1].strip(' ').strip("\"")
        helptext[key]=desc
    return helptext

#ini_get_all 获取php所有配置项
def ini_get_all()->dict:
    conf={}
    lines=open('clinta.phpipam.ini').readlines()
    for line in lines:
        line.strip()
        line=line.split('=')
        if len(line)>=2:
            k=line[0].strip()
            v=line[1].strip()
            conf[k]=v
    return conf
# print(ini_get_all())
def is_readable(value)->bool:
    pass
def error_reporting():
    pass
def realpath(value):
    pass
def is_writable(value):
    pass
def is_writable_or_chmodable(value):
    pass
def strncmp(a,b,c):
    pass
#检测变量是否已设置并且非None
def isset(value)->bool:
    if value==None:
        return False
    return True

def tres(meta,result,reason=None,recommentation=None):

    pass

def test_all_ini_entries(helptext):
    global cfg
    kv_dict=ini_get_all()
    for key,value in kv_dict.items():
        print("{}={}".format(key,value))

        # print(meta)
        result=None
        reason=None
        recommendation=None
        if key in helptext.keys():
            recommendation=helptext[key]
        # ignore=0
        if key=="display_errors":
            if is_on(value):
                result,reason=(TEST_MEDIUM,"display_errors is on.")
        elif key=="display_startup_errors":
            if is_on(value):
                result, reason = (TEST_MEDIUM, "display_startup_errors is on.")
        elif key=="log_errors":
            if is_on(value):
                result, reason = (TEST_LOW, "You are not logging errors.")
        elif key=="expose_php":
            if is_on(value):
                result,reason=(TEST_LOW,"PHP is exposed by HTTP headers.")
        elif key=="max_execution_time":
            if intval(value)==0:
                result,reason=(TEST_MEDIUM, "Execution time is not limited.")
            elif intval(value)>=300:
                result, reason = (TEST_LOW, "Execution time limit is rather high.")
        elif key=="max_input_time":
            if value=="-1":
                result,reason=(TEST_MAYBE,"Input parsing time not limited.")
        elif key=="max_input_nesting_level":
            if intval(value)>128:
                result, reason = (TEST_MEDIUM, "Input nesting level extremely high.")
            elif intval(value)>64:
                result,reason = (TEST_MAYBE, "Input nesting level higher than usual.")
        elif key=="max_input_vars":
            if intval(value)>5000:
                result, reason = (TEST_MEDIUM, "Extremely high number.")
            elif intval(value)>1000:
                result, reason = (TEST_MAYBE, "Higher number than usual.")
        elif key=="memory_limit": #memory_limit=-1表示没有内存限制
            if value==-1:
                result, reason = (TEST_HIGH, "Memory limit deactivated.")
            elif ini_atol(value) >= 128*1024*1024: # default value
                result, reason = (TEST_MAYBE, "Memory limit is 128M or more.")
        elif key=='post_max_size':
            tmp = ini_atol(kv_dict['memory_limit'])
            value=ini_atol(value)
            if tmp<0:
                if value>=ini_atol('2G'):
                    result,reason=(TEST_MAYBE, "post_max_size is >= 2G.")
            if value>tmp:
                result,reason=(TEST_HIGH, "post_max_size is greater than memory_limit.")
                recommendation=helptext['post_max_size>memory_limit']
        elif key=="upload_max_filesize":
            if value=="2M":
                result, reason =TEST_COMMENT, "default value."
            elif ini_atol(value)>=ini_atol("2G"):
                result, reason =TEST_MAYBE, "value is rather high."
        elif key=="max_file_uploads":
            if intval(value)>30:
                result,reason=TEST_MAYBE,"value is rather high."
        elif key=='allow_url_fopen':
            if is_on(value):
                result,reason=TEST_HIGH, "fopen() is allowed to open URLs."
        elif key=='allow_url_include':
            if is_on(value):
                result,reason=TEST_HIGH, "include/require() can include URLs."
        elif key == 'magic_quotes_gpc':
            if is_on(value):
                result, reason = (TEST_HIGH, "magic quotes activated.")
                recommendation = helptext['magic_quotes']
        elif key == 'magic_quotes_runtime':
            if is_on(value):
                result, reason = (TEST_HIGH, "magic quotes activated.")
                recommendation = helptext['magic_quotes']
        elif key == 'magic_quotes_sybase':
            if is_on(value):
                result, reason = (TEST_HIGH, "magic quotes activated.")
                recommendation = helptext['magic_quotes']
        elif key=="enable_dl":
            if is_on(value):
                result, reason =(TEST_HIGH, "PHP can load extensions during runtime.")
        elif key=="disable_functions":
            value=ini_list(value)
            if value==False:
                result, reason = (TEST_MEDIUM, "no functions disabled.")
        elif key=="disable_classes":
            value=ini_list(value)
            if value==False:
                result, reason = (TEST_MEDIUM, "no functions disabled.")
        elif key=="request_order":
            value=value.upper()
            if value=="GP":
                continue
            if 'C' in value:
                result,reason=(TEST_MAYBE, "cookie values in $_REQUEST.")
            if 'PG' in value.replace('C',''):
                result, reason = (TEST_LOW, "GET overrides POST in $_REQUEST.")
        elif key=="auto_globals_jit":
            result = TEST_OK
        elif key=="register_globals":
            if value!="" and value!="0":
                result, reason =(TEST_CRITICAL, "register_globals is on.")
        elif key=="file_uploads":
            if value=="1":
                result, reason = (TEST_MAYBE, "file uploads are allowed.")
        elif key=='filter.default':
            if value!="unsafe_raw":
                result, reason = (TEST_MAYBE, "default input filter set.")
        elif key=='open_basedir':
            if value=="":
                result, reason = (TEST_LOW, "open_basedir not set.")
        elif key=='session.save_path':
            if value=="":
                result, reason = (TEST_MAYBE, "session save path not set.")
        elif key=='session.cookie_httponly':
            if is_on(value)==False:
                result, reason = (TEST_MAYBE, "no implicit httpOnly-flag for session cookie.")
        elif key=='session.cookie_secure':
            if is_on(value)==False:
                result, reason = (TEST_MAYBE, "no implicit secure-flag for session cookie.")
        elif key=='session.cookie_lifetime':
            if is_on(value)==False:
                result, reason = (TEST_MAYBE, "no implicit lifetime for session cookie.")
        elif key=='session.cookie_samesite':
            if value=="":
                result, reason = (TEST_MAYBE, "no implicit secure-flag for session cookie.")
            elif value!="Strict":
                result, reason = (TEST_COMMENT,"SameSite is not set to `Strict`. If cross-site GET requests to your site are unlikely, this should be set to `Strict`.")
        elif key=='session.referer_check':
            if value=="":
                result, reason = (TEST_COMMENT, "referer check not activated.")
        elif key=='session.use_strict_mode':
            if is_on(value)==False:
                result, reason = (TEST_MEDIUM, "strict mode not activated.")
        elif key=='session.use_cookies':
            if is_on(value)==False:
                result, reason = (TEST_HIGH, "Session ID not stored in cookie.")
        elif key=='session.use_only_cookies':
            if is_on(value)==False:
                result, reason = (TEST_HIGH, "Session ID not limited to cookie.")
        elif key=='session.name':
            if value=="PHPSESSID":
                result, reason = (TEST_COMMENT, "default session name.")
        elif key=='session.use_trans_sid':
            if is_on(value)==True:
                result, reason = (TEST_HIGH, "transparent SID active.")
        elif key=='always_populate_raw_post_data':
            if is_on(value)==True:
                result, reason = (TEST_COMMENT, "HTTP_RAW_POST_DATA is available.")
        elif key=="arg_separator.input":
            pass
        elif key=="arg_separator.output":
            if value!="&":
                result, reason =(TEST_MAYBE, "unusual arg separator.")
                recommendation = helptext['arg_separator']
        elif key=='assert.active':
            if is_on(value)==True:
                result, reason=(TEST_MEDIUM, "assert is active.")
        elif key=='assert.callback':
            if kv_dict['assert.active'] and value!= "" and value!=None:
                result, reason =(TEST_MEDIUM, "assert callback set.")
        elif key=="zend.assertions":
            if intval(value)>0:
                result, reason =(TEST_MEDIUM, "assert is active.")
        elif key=='auto_append_file':
            pass
        elif key=='auto_prepend_file':
            if value!=None and value!="":
                result, reason = (TEST_MAYBE, "$k is set.")
                recommendation = helptext['auto_append_file']
        elif key=='cli.pager':
            if value!=None and value!="":
                result, reason = (TEST_MAYBE, "CLI pager set.")
        elif key=='cli.prompt':
            if value!=None and len(value)>32:
                result, reason = (TEST_MAYBE, "CLI prompt is rather long (>32).")
        elif key=='curl.cainfo':
            if value!="":
                if value[0]!=DIRECTORY_SEPARATOR or cfg['is_win'] and value[1]!=":"+DIRECTORY_SEPARATOR:
                    result, reason = (TEST_LOW, "CURLOPT_CAINFO must be an absolute path.")
                elif not is_readable(value):
                    result, reason = (TEST_LOW, "CURLOPT_CAINFO is set but not readable.")
        elif key == 'docref_root':
            pass
        elif key == 'docref_ext':
            if value!=None and value!="":
                result, reason = (TEST_LOW, "docref is set.")
                recommendation = helptext['docref_*']
            elif value=='default_charset':
                result, reason = (TEST_HIGH, "default charset not explicitly set.")
                recommendation = helptext['default_charset=empty']
            elif re.match("iso-8859",value)!=None:
                result, reason= (TEST_MAYBE, "charset without multibyte support.")
                recommendation = helptext['default_charset=iso-8859']
            elif value.lower() == "utf8":
                result, reason= (TEST_HIGH, "'UTF-8' misspelled (without dash).")
                recommendation = helptext['default_charset=typo']
            elif value.lower() == "utf-8":
                pass
            else:
                result, reason = (TEST_COMMENT, "custom charset.")
                recommendation = helptext['default_charset=custom']
        elif key=="default_mimetype":
            if value=="":
                result, reason = (TEST_HIGH, "default mimetype not set.")
        elif key=="default_socket_timeout":
            if value=="":
                result, reason = (TEST_LOW, "default socket timeout rather big.")
        elif key=="doc_root":
            if not cfg["is_cgi"]:
                result, reason = (TEST_SKIPPED, "no CGI environment.")
            elif kv_dict['cgi.force_redirect']:
                result, reason= (TEST_SKIPPED, "cgi.force_redirect is on instead.")
            elif value=="":
                result, reason = (TEST_MEDIUM, "doc_root not set.")
                recommendation = helptext['doc_root=empty']
        elif key=='error_prepend_string':
            pass
        elif key=='error_append_string':
            if value!=None and value!="":
                result, reason = (TEST_MAYBE, "$k is set.")
                recommendation = helptext['error_append_string']
        elif key=='error_reporting':#?????????????????????
            if error_reporting() == 0:
                result, reason = (TEST_LOW, "error reporting is off.")
        elif key=="extension_dir":
            if value!=None and value!="":
                if realpath(value) == False:
                    result, reason = (TEST_SKIPPED, "path is invalid or not accessible.")
                elif is_writable(value) or is_writable_or_chmodable(value):
                    result, reason= (TEST_HIGH, "path is writable or chmod-able.")
        elif key=='exit_on_timeout':#????????????????
            if isset(_SERVER["SERVER_SOFTWARE"])==False or strncmp(_SERVER["SERVER_SOFTWARE"], "Apache/1", len("Apache/1")) != 0:
                result, reason = (TEST_SKIPPED, "only relevant for Apache 1.")
            elif is_on(value)==False:
                result, reason = (TEST_LOW, "not enabled.")
        elif key=='filter.default':
            if value != "unsafe_raw":
                result, reason = (TEST_MAYBE, "global input filter is set.")
        elif key=='highlight.comment':
            pass
        elif key=='highlight.default':
            pass
        elif key=='highlight.html':
            pass
        elif key=='highlight.keyword':
            pass
        elif key=='highlight.string':#?????
            if True:
                result, reason= (TEST_MEDIUM, "suspicious color value.")
                recommendation = helptext['highlight.*']
        elif key=='iconv.internal_encoding':
            pass
        elif key=='iconv.input_encoding':
            pass
        elif key=='iconv.output_encoding':
            if PHP_MAJOR_VERSION > 5 or PHP_MAJOR_VERSION == 5 and PHP_MINOR_VERSION >= 6:
                if value != "":
                    result, reason = (TEST_COMMENT, "not empty.")
                    recommendation = helptext['iconv.internal_encoding!=empty']
                else:
                    result, reason = (TEST_SKIPPED, "not PHP >=5.6")
        elif key=="asp_tags":
            if is_on(value):
                result, reason = (TEST_MAYBE, "ASP-style tags enabled.")
        elif key=="ldap.max_links":
            if intval(value)==-1:
                result, reason = (TEST_MAYBE, "Number of LDAP connections not limited.")
            elif intval(value)>5:
                result, reason = (TEST_MAYBE, "More than 5 LDAP connections allowed.")
        elif key=='log_errors_max_len':
            value=ini_atol(value)
            if value==0 or value>4096:
                result, reason = (TEST_MEDIUM, "Value rather big or not limited.")
        elif key== 'mail.add_x_header':
            if value:
                result, reason = (TEST_MEDIUM, "Filename exposed.")
        elif key== 'mail.force_extra_parameters':
            if value:
                result, reason = (TEST_COMMENT, "not empty.")
                recommendation = "just FYI."
        elif key == 'intl.default_locale':
            if value=="":
                result, reason = (TEST_COMMENT, "ICU default locale not set.")
        elif key == 'intl.error_level':
            if intval(value) and E_ERROR:
                result, reason = (TEST_MAYBE, "ICU functions fail with error.")
        elif key == 'intl.use_exceptions':
            if is_on(value):
                result, reason = (TEST_MAYBE, "intl functions throw exceptions.")
        elif key == 'last_modified':
            if is_on(value):
                result, reason = (TEST_LOW, "is set.")
        elif key == 'zend.multibyte':
            if is_on(value):
                result, reason = (TEST_HIGH, "Multibyte encodings are active.")
        elif key == 'runkit.internal_override':
            if is_on(value):
                result, reason = (TEST_CRITICAL, "Internal functions override is enabled")

        elif key == 'phar.readonly':
            if not is_on(value):
                result, reason = (TEST_LOW, "Phar files aren't readonly.")
        elif key == 'phar.require_hash':
            if not is_on(value):
                result, reason = (TEST_LOW, "Signature check for phar is disabled.")
        elif key == 'ffi.enable':
            if not is_on(value):
                result, reason = (TEST_HIGH, "FFI is enabled.")

        #known, but extra check below
        elif key == 'error_log':
            pass
        elif key == 'include_path':
            pass
        elif key == 'mail.log':
            pass
        elif key == 'upload_tmp_dir':
           #silently ignore this option
            ignore = 1
    #known, but probably not security relevent

        elif key == 'precision':
            pass
        elif key == 'assert.bail':
            pass
        elif key == 'assert.quiet_eval':
            pass
        elif key == 'assert.warning':
            pass
        elif key == 'assert.exception':
            pass
        elif key == 'auto_detect_line_endings':
            pass
        elif key == 'bcmath.scale':
            pass
        elif key == 'browscap':
            pass
        elif key == 'date.default_latitude':
            pass
        elif key == 'date.default_longitude':
            pass
        elif key == 'date.sunrise_zenith':
            pass
        elif key == 'date.sunset_zenith':
            pass
        elif key == 'date.timezone':
            pass
        elif key == 'dba.default_handler':
            pass
        elif key == 'enable_post_data_reading':
            pass
        elif key == 'engine': # can only be 1 here anyway
            pass
        elif key =='exif.decode_jis_intel':
            pass
        elif key =='exif.decode_jis_motorola':
            pass
        elif key =='exif.decode_unicode_intel':
            pass
        elif key =='exif.decode_unicode_motorola':
            pass
        elif key =='exif.encode_jis':
            pass
        elif key =='exif.encode_unicode':
            pass
        elif key =='filter.default_flags':
            pass
        elif key =='from':
            pass
        elif key =='gd.jpeg_ignore_warning':
            pass
        elif key =='html_errors':
            pass
        elif key =='ignore_repeated_errors':
            pass
        elif key =='ignore_repeated_source':
            pass
        elif key =='ignore_user_abort':
            pass
        elif key =='implicit_flush':
            pass
        elif key =='report_memleaks': #may be relevant, but only active in debug builds anyway
            pass
        elif key =='session.auto_start':
            pass
        elif key =='session.cache_expire':
            pass
        elif key =='session.cache_limiter':
            pass
        elif key =='short_open_tag':
            pass
        elif key =='track_errors':
            result, reason = (TEST_OK, "any value is ok")
        else:
            result, reason = (TEST_UNKNOWN, "unknown / not checked.")

        # if ignore:
        #     continue
        meta = "php.ini / {}".format(key)
        # print("*******************result",result)
        if result == None:
            # print("result = None")
            print_res(meta, TEST_OK)
            # print("dhhkdfhgkjdfgjkdkjfgndf")
        elif result ==TEST_SKIPPED:
            # print("result=TEST_SKIPPED")
            print_res(meta, result, reason)
        else:
            # print("result={}".format(result))
            print_res(meta, result, reason, recommendation)


#;
#result,reason=


if __name__=='__main__':
    #test
    # print(ini_atol('1kB'))
    helptext=parse_helptext()
    # print(helptext)
    test_all_ini_entries(helptext)



