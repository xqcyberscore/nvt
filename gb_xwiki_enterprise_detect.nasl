###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xwiki_enterprise_detect.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# XWiki Enterprise Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-02-17
#  - Updated to set KB if XWiki is installed
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "XWiki Enterprise Version Detection.

The script detects the version of XWiki Enterprise on remote host
and sets the KB.";

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801840";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("XWiki Enterprise Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Variables Initialization
port  = 0;
dir  = "";
sndReq = "";
rcvRes = "";
info   = "";
dump   = "";
tmp_version = "";
ver  = NULL;

## Get http port
port = get_http_port(default:8080);

if(!port){
  exit(0);
}

dir = "/xwiki";

## Send and Receive the response
sndReq = http_get(item:dir +"/bin/view/Main/", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && "XWiki Enterprise" >< rcvRes)
{
  ## Get XWiki Enterprise Version and set KB
  ver = eregmatch(pattern:'>XWiki Enterprise ([0-9.]+)', string:rcvRes);

  dump = ver;

  if(ver[1])
  {
    tmp_version = ver[1] + " under " + dir;
    ver = ver[1];
  }
  else
  {
    tmp_version = "under " + dir;
    ver = "unknown";
  }

  ## Set the KB value
  set_kb_item(name:"www/" + port + "/XWiki", value:tmp_version);
  set_kb_item(name:"xwiki/installed",value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:xwiki:xwiki:");
  if(isnull(cpe))
     cpe = 'cpe:/a:xwiki:xwiki:';

  register_product(cpe:cpe, location:dir, port:port);

  log_message(data: build_detection_report(app:"XWiki",
                                         version: ver,
                                         install:dir,
                                         cpe:cpe,
                                         concluded: dump[max_index(dump)-1]),
                                         port: port);

  exit(0);
}
