###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_xss_vuln.nasl 4218 2016-10-05 14:20:48Z teissa $
#
# AWStats awstats.pl XSS Vulnerability - Dec08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800151");
  script_version("$Revision: 4218 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-05 16:20:48 +0200 (Wed, 05 Oct 2016) $");
  script_tag(name:"creation_date", value:"2008-12-09 13:27:23 +0100 (Tue, 09 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5080");
  script_name("AWStats awstats.pl XSS Vulnerability - Dec08");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=474396");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "affected" , value : "AWStats 6.8 and earlier.");
  script_tag(name : "insight" , value : "The flaw is due to query_string parameter in awstats.pl which is not
  properly sanitized before being returned to the user.");
  script_tag(name : "summary" , value : "The host is running AWStats, which is prone to XSS Vulnerability.");
  script_tag(name : "solution" , value : "Update to higher Version or Apply patches from,
  http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432#21

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****");
  script_tag(name : "impact" , value : "Successful attack could lead to execution of arbitrary HTML and
  script code in the context of an affected site.

  Impact Level: Application

  NOTE: This issue exists because of an incomplete fix for CVE-2008-3714.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/awstats/wwwroot/cgi-bin", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/awstats.pl", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);

  if("Advanced Web Statistics" >< rcvRes)
  {
    awVer = eregmatch(pattern:"AWStats ([0-9.]+)", string:rcvRes);
    if(awVer[1] != NULL && version_is_less_equal(version:awVer[1],
                                                 test_version:"6.8")){
     security_message(port:port);
     exit(0);
    }
  }
}

exit(99);