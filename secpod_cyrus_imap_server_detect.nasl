###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cyrus_imap_server_detect.nasl 2833 2016-03-11 08:36:30Z benallard $
#
# Cyrus IMAP Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_summary = "This script finds the running version of Cyrus IMAP Server
  and saves the result in KB.";

if(description)
{
  script_id(902220);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2833 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 09:36:30 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Cyrus IMAP Server Version Detection");

  script_summary("Set the version of Cyrus IMAP Server in KB");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/imap", 143);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

port = get_kb_item("Services/imap");
if(!port){
  port = 143;
}

banner = get_kb_item(string("imap/banner/", port));
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    {
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}

if(!banner){
  exit(0);
}

if(("Cyrus IMAP" >< banner && "server ready" >< banner))
{

  imapVer = eregmatch(pattern:"IMAP v([0-9.]+)", string:banner);
  if(!isnull(imapVer[1]))
  {
    set_kb_item(name:"Cyrus/IMAP4/Server/Ver", value:imapVer[1]);
    set_kb_item(name:"Cyrus/IMAP4/Server/port", value:port);
    log_message(data:"Cyrus IMAP4 server " + imapVer[1] +
                  " was detected on the host", port:port);
  }
}
