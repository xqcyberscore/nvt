###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_default_login.nasl 3911 2016-08-30 13:08:37Z mime $
#
# Dell Remote Access Controller Default Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

tag_summary = "The remote Dell Remote Access Controller is prone to a
default account authentication bypass vulnerability. This issue may be
exploited by a remote attacker to gain access to sensitive information
or modify system configuration without requiring authentication.";


tag_solution = "Change the password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103681";  
CPE = 'cpe:/h:dell:remote_access_card'; 

if (description)
{
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 3911 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-30 15:08:37 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Dell Remote Access Controller Default Login");
 script_summary("Checks for the presence of Dell Remote Access Controller");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_dell_drac_detect.nasl");
 script_require_ports("Services/www", 443);
 script_mandatory_keys("dell_remote_access_controller/version");
 exit(0);
}

include("http_func.inc"); 
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

version = get_kb_item("dell_remote_access_controller/version");
if(!version)exit(0);

function check_iDRAC_default_login(version) {

  if(!version || version !~ "^[4-7]$")return FALSE;

  user = 'root';
  pass = 'calvin';

  if(version == "4") {
    urls = make_list('/cgi/login');
    posts = make_list('user=' + user + '&hash=' + pass);
    login_success = make_list('top.location.replace("/cgi/main")');
  }  

  else if(version == 5) {
    urls = make_list('/cgi-bin/webcgi/login');
    posts = make_list('user=' + user + '&password=' + pass);
    login_fail = '<RC>0x140004</RC>';
  }  

  else if(version == 6 || version == 7) {
    urls = make_list('/data/login','/Applications/dellUI/RPC/WEBSES/create.asp');
    posts = make_list('user=' + user + '&password=' + pass, 'WEBVAR_PASSWORD=' + pass  + '&WEBVAR_USERNAME=' + user  + '&WEBVAR_ISCMCLOGIN=0');
    login_success = make_list('<authResult>0</authResult>',"'USERNAME' : 'root'");
  }  

  else {
    return FALSE;
  }  

  host = get_host_name();

  foreach url (urls) {

    foreach post (posts) {

      buf = FALSE;

      sleep(1);

      soc = open_sock_tcp(port);
      if(!soc) return FALSE;

      len = strlen(post);
 
      req = string("POST ",url," HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS/6.0\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: en-us;q=0.5,en;q=0.3\r\n",
                 "DNT: 1\r\n",
                 "Accept-Encoding: identity\r\n",
                 "Connection: keep-alive\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                 post);

      send(socket:soc, data:req);
      while(recv = recv(socket:soc, length:1024)) {
        buf += recv;
      }  

      close(soc);

      if(buf !~ "HTTP/1\.. 200") continue;

      if("Content-Encoding: gzip" >< buf) buf = http_gunzip(buf:buf);

      if(login_fail && login_fail >!< buf) {
        return TRUE;
      }

      if(login_success) { 
        foreach ls (login_success) {
          if(ls >< buf) {
            return TRUE;
          }  
        }  
      }

    }
  }  
}

if(check_iDRAC_default_login(version:version)) {

  message = 'It was possible to login with username "root" and password "calvin".\n';
  security_message(port:port, data:message);
  exit(0);

}

exit(99);
