###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vicidial_mult_sql_inj_vuln.nasl 5148 2017-01-31 13:16:55Z teissa $
#
# VICIDIAL Call Center Suite Multiple SQL Injection Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900916");
  script_version("$Revision: 5148 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 14:16:55 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2234");
  script_bugtraq_id(35056);
  script_name("VICIDIAL Call Center Suite Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8755");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50665");
  script_xref(name : "URL" , value : "http://www.eflo.net/VICIDIALforum/viewtopic.php?t=8075");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Attackers can exploit this issue via specially crafted SQL statements to
  access and modify the back-end database.

  Impact Level: Application");
  script_tag(name : "affected" , value : "VICIDIAL Call Center Suite 2.0.5 through 2.0.5-173");
  script_tag(name : "insight" , value : "This flaw occurs due to lack of sanitation of user supplied data passed into
  the admin.php and can be exploited via username and password parameters.");
  script_tag(name : "summary" , value : "This host is installed with VICIDIAL Call Center Suite and is
  prone to multiple SQL Injection vulnerabilities.");
  script_tag(name : "solution" , value : "Apply the available patch.
  http://www.eflo.net/vicidial/security_fix_admin_20090522.patch

  *****
  NOTE: Ignore this warning if the above mentioned patch is already applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

viciPort = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:viciPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/www/agc", "/agc", "/vicidial", cgi_dirs(port:viciPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item: dir + "/vicidial.php", port:viciPort);
  rcvRes = http_keepalive_send_recv(port:viciPort, data:sndReq);

  if((rcvRes != NULL) && ("VICIDIAL web client" >< rcvRes))
  {
    viciVer = eregmatch(pattern:"VERSION: (([0-9.]+)-?([0-9]+)?)", string:rcvRes);
    viciVer[1] = ereg_replace(pattern:"-", replace:".", string:viciVer[1]);

    if(viciVer[1] != NULL)
    {
      if(version_is_less_equal(version:viciVer[1], test_version:"2.0.5.206"))
      {
        security_message(port:viciPort);
        exit(0);
      }
    }
  }
}

exit(99);