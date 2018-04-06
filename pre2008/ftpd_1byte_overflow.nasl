# OpenVAS Vulnerability Test
# $Id: ftpd_1byte_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: BSD ftpd Single Byte Buffer Overflow
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

tag_summary = "One-byte buffer overflow in replydirname function
in BSD-based ftpd allows remote attackers to gain
root privileges.";

tag_solution = "upgrade your FTP server.
Consider removing directories writable by 'anonymous'.";

# TODO: check banner!
# exploit is available at:
# http://www.securityfocus.com/data/vulnerabilities/exploits/7350oftpd.tar.gz

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11371");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2124);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2001-0053");
 name = "BSD ftpd Single Byte Buffer Overflow";
 script_name(name);
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("FTP");

 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");

 script_dependencies("find_service.nasl", "ftp_writeable_directories.nasl");
 script_mandatory_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if(safe_checks())
{
 banner = get_ftp_banner(port: port);
 
 #TODO
 
 exit(0);
}


function on_exit()
{
  soc = open_sock_tcp(port);
  if ( soc )
  {
  ftp_log_in(socket:soc, user:login, pass:pass);
  send(socket:soc, data:string("CWD ", wri, "\r\n"));
  r = ftp_recv_line(socket:soc);
  for(j=0;j<num_dirs - 1;j=j+1)
  {
   send(socket:soc, data:string("CWD ", crap(144), "\r\n"));
   r = ftp_recv_line(socket:soc);
  }

  for(j=0;j<num_dirs;j=j+1)
  {
   send(socket:soc, data:string("RMD ", crap(144),  "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(!ereg(pattern:"^250 .*", string:r))exit(0);
   send(socket:soc, data:string("CWD ..\r\n"));
   r = ftp_recv_line(socket:soc);
  }
 }
}


# First, we need anonymous access

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);

# Then, we need a writeable directory
wri = get_kb_item("ftp/writeable_dir");
if(!wri)exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 if(ftp_log_in(socket:soc, user:login, pass:pass))
 {
  num_dirs = 0;
  # We are in

  c = string("CWD ", wri, "\r\n");
  send(socket:soc, data:c);
  b = ftp_recv_line(socket:soc);
  cwd = string("CWD ", crap(144), "\r\n");
  mkd = string("MKD ", crap(144), "\r\n");
  rmd = string("RMD ", crap(144), "\r\n");
  pwd = string("PWD \r\n");

  #
  # Repeat the same operation 20 times. After the 20th, we
  # assume that the server is immune.
  #


  for(i=0;i<20;i=i+1)
  {
  send(socket:soc, data:mkd);
  b = ftp_recv_line(socket:soc);

  # No answer = the server has closed the connection.
  # The server should not crash after a MKD command
  # but who knows ?

  if(!b){
  	#security_message(port);
	exit(0);
	}

  if(!ereg(pattern:"^257 .*", string:b))
  {
   i = 20;
  }
  else
  {
  send(socket:soc,data:cwd);
  b = ftp_recv_line(socket:soc);
  send(socket:soc, data:rmd);

  #
  # See above. The server is unlikely to crash
  # here

  if(!b)
       {
  	#security_message(port);
	exit(0);
       }

   if(!ereg(pattern:"^250 .*", string:b))
   {
    i = 20;
   }
   else num_dirs = num_dirs + 1;
   }
  }

  #
  #If vunerable, it will crash here
  #
  send(socket:soc,data:pwd);
  b = ftp_recv_line(socket:soc);
  if(!b)
       {
  	security_message(port);
	exit(0);
       }
 

  ftp_close(socket:soc);
 }
}
