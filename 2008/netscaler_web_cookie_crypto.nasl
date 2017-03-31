# OpenVAS Vulnerability Test
# $Id: netscaler_web_cookie_crypto.nasl 4489 2016-11-14 08:23:54Z teissa $
# Description: NetScaler web management cookie cipher weakness
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2007 nnposter
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server is prone to an information disclosure attack. 

Description :

The version of the Citrix NetScaler web management interface on the
remote host uses weak encryption for protecting the HTTP cookie
content by XORing sensitive values, including the username and
password, with a fixed key stream.";

tag_solution = "Do not stay logged into the NetScaler web management interface while
browsing other web sites.";

# History:
# 1.00, 11/21/07
# - Initial release

if (description)
    {
    script_id(80022);
    script_version("$Revision: 4489 $");
    script_tag(name:"last_modification", value:"$Date: 2016-11-14 09:23:54 +0100 (Mon, 14 Nov 2016) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"4.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
    name="NetScaler web management cookie cipher weakness";
    summary="Tests NetScaler web management cookie encryption";
    family="Web Servers";
    script_name(name);
    script_family(family);
    script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
    script_cve_id("CVE-2007-6192");
    script_copyright("This script is Copyright (c) 2007 nnposter");
    script_dependencies("netscaler_web_login.nasl");
    script_require_keys("www/netscaler","http/password");
    script_require_ports("Services/www",80);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/484182/100/0/threaded");
    exit(0);
    }


if (!get_kb_item("www/netscaler")) exit(0);
if (!get_kb_item("http/password")) exit(0);


include("misc_func.inc");
include("url_func.inc");
include("http_func.inc");

function cookie_decode (cookie,parm)
{
local_var match;
match=eregmatch(string:cookie,pattern:' '+parm+'=([^; \r\n]*)',icase:TRUE);
if (isnull(match)) return NULL;
return base64_decode(str:urldecode(estr:match[1])-'\n');
}


function str_xor ()
{
local_var nargs,result,len,arg1,arg2,i,j;
nargs=max_index(_FCT_ANON_ARGS);
if (nargs==0) return NULL;
result=_FCT_ANON_ARGS[0];
len=strlen(result);
for (i=1; i<nargs; ++i)
    {
    arg1=result;
    arg2=_FCT_ANON_ARGS[i];
    if (len!=strlen(arg2)) return NULL;
    result="";
    for (j=0; j<len; ++j) result+=raw_string(ord(arg1[j])^ord(arg2[j]));
    }
return result;
}


function strleft ()
{
return substr(_FCT_ANON_ARGS[0],0,_FCT_ANON_ARGS[1]-1);
}


port=get_http_port(default:80);
if (!get_kb_item("www/netscaler/"+port)) exit(0);
cookie=get_kb_item("/tmp/http/auth/"+port);
if (!cookie) exit(0);

hostname=get_host_name();
if (!hostname) hostname=get_host_ip();
keystream=str_xor(hostname,cookie_decode(cookie:cookie,parm:"ns3"));
if (!keystream || strlen(keystream)==0) exit(0);

ns2=cookie_decode(cookie:cookie,parm:"ns2");
ns2len=strlen(ns2);
keylen=strlen(keystream);
if (ns2len<keylen) len=ns2len;
else len=keylen;
guess=str_xor(strleft(ns2,len),strleft(keystream,len));
if (!guess || strlen(guess)==0) exit(0);
if (strleft(get_kb_item("http/password"),len)!=guess) exit(0);

report = string(
    "Sensitive values, including the username and password, can be\n",
    "decrypted by XORing the plaintext with the following fixed key\n",
    "stream :\n",
    "\n",
    hexstr(keystream), "..."
);
security_message(port:port,data:report);
