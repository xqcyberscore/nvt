###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_detect.nasl 4890 2016-12-30 13:26:31Z antu123 $
#
# Apache Hadoop Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810317");
  script_version("$Revision: 4890 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-30 14:26:31 +0100 (Fri, 30 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-23 11:51:30 +0530 (Fri, 23 Dec 2016)");
  script_name("Apache Hadoop Version Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of Apache Hadoop.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 50070);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

req = "";
rcvRes = "";
version = "";
ver = "";
url = "";
install = "";

##Get HTTP Port
if(!hadoopPort = get_http_port(default:50070)){
  exit(0);
}

url = "/dfshealth.jsp";

## Send and receive response
req = http_get(item: url, port: hadoopPort);
rcvRes = http_keepalive_send_recv(port:hadoopPort, data:req);

## Confirm the application
if(rcvRes =~ "HTTP/1.. 200" && ">Cluster Summary<" >< rcvRes
         && (("Apache Hadoop<" >< rcvRes) || (">Hadoop<" >< rcvRes)))
{
  install = "/";

  ## Grep for the version
  ver = eregmatch( pattern:'> *Version:.*<td> *([0-9.]+),', string:rcvRes);

  if(ver[1]){
    version = ver[1];
    set_kb_item(name:"Apache/Hadoop/Ver", value:version);
  }
  else{
    version = "unknown";
  }

  ## Set the KB value
  set_kb_item(name:"Apache/Hadoop/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:hadoop:");
  if( ! cpe )
    cpe = "cpe:/a:apache:hadoop";

  register_product(cpe:cpe, location:install, port:hadoopPort);

  log_message(data:build_detection_report(app:"Apache Hadoop",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version),
                                          port:hadoopPort);
}
exit(0);
