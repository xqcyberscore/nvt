###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freeradius_tunnel_password_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# FreeRADIUS Tunnel-Password Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By:
# Antu Sanadi <santu@secpod.com> on 2009/12/31 #6502
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

tag_solution = "Upgrade to version 1.1.8
  http://freeradius.org/download.html
  or
  Apply patch from below link,
  http://github.com/alandekok/freeradius-server/commit/860cad9e02ba344edb0038419e415fe05a9a01f4

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to crash the service.
  Impact Level: Application";
tag_affected = "FreeRADIUS version prior to 1.1.8";
tag_insight = "The flaws are due to:
  - An error in the 'rad_decode()' function in 'src/lib/radius.c' which can
    be exploited via zero-length Tunnel-Password attributes.
  - An unspecified error that can be exploited to crash the 'radiusd' daemon.";
tag_summary = "This host is running FreeRADIUS and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900856");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3111");
  script_bugtraq_id(36263);
  script_name("FreeRADIUS Tunnel-Password Denial Of Service Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36509");
  script_xref(name : "URL" , value : "http://www.intevydis.com/blog/?p=66");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/09/09/1");
  script_xref(name : "URL" , value : "http://www.braindeadprojects.com/blog/what/freeradius-packet-of-death/");
  script_xref(name : "URL" , value : "https://lists.freeradius.org/pipermail/freeradius-users/2009-September/msg00242.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_freeradius_detect.nasl");
  script_require_keys("FreeRADIUS/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

foreach radius_port (make_list(1812, 1813, 1814))
{
  if(get_udp_port_state(radius_port))
  {
    freeradiusVer = get_kb_item("FreeRADIUS/Ver");
    if(freeradiusVer)
    {
      # Check for FreeRADIUS version < 1.1.8
      if(version_is_less(version:freeradiusVer, test_version:"1.1.8")){
        security_message(port:radius_port, proto:"udp");
      }
    }
    exit(0);
  }
}
