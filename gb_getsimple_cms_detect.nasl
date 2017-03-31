###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_detect.nasl 4624 2016-11-25 07:00:59Z cfi $
#
# GetSimple CMS version detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801550");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 4624 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 08:00:59 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("GetSimple CMS version detection");

  script_summary("Set the version of GetSimple CMS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "summary" , value : "This script finds the running GetSimple CMS version and saves
  the result in KB.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Get HTTP Port
cmsPort = get_http_port(default:80);

if (!can_host_php(port:cmsPort)) exit(0);

foreach dir (make_list_unique("/GetSimple", "/GetSimple_2.01" , cgi_dirs(port:cmsPort)))
{

  install = dir;
  if(dir == "/") dir = "";

  ## Send and Receive request
  sndReq = http_get(item:string(dir, "/index.php"), port:cmsPort);
  rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

  ## Confirm application is GetSimple CMS
  if(">Powered by GetSimple<" >< rcvRes)
  {
    ## Grep the version
    cmsVer = eregmatch(pattern:"> Version ([0-9.]+)<" , string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      tmp_version = cmsVer[1] + " under " + install;
      set_kb_item(name:"www/" + cmsPort + "/GetSimple_cms",
                value:tmp_version);
      log_message(data:"GetSimple version " + cmsVer[1] + " running at location "
                    + install + " was detected on the host");
  
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:getsimple:getsimple:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe);

    }
  }
}
