###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcachedb_detect.nasl 4817 2016-12-20 15:32:25Z cfi $
#
# MemcacheDB Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800716");
  script_version("$Revision: 4817 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-20 16:32:25 +0100 (Tue, 20 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MemcacheDB Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Service detection");
  script_require_ports(21201);

  script_tag(name:"summary", value:"The script detects the installed version of MemcacheDB and sets
  the result into KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


# Default port used by MemcacheDB Daemon
memcachedbPort = 21201;
if(!get_port_state(memcachedbPort)){
  exit(0);
}

data = string("version \r\n");
dbappsock = open_sock_tcp(memcachedbPort);
if(dbappsock)
{
  send(socket:dbappsock, data:data);
  response = recv(socket:dbappsock, length:1024);
  close(dbappsock);
  if(response != NULL)
  {
    version = eregmatch(pattern:"VERSION ([0-9.]+)", string:response);
    if(version[1] != NULL)
    {
      set_kb_item(name:"MemCacheDB/Ver", value:version[1]);
      log_message(data:"MemCacheDB version " + version[1] +
                      " was detected on the host");
    }
  }
}
