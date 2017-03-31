###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pango_bof_vuln.nasl 5122 2017-01-27 12:16:00Z teissa $
#
# Pango Integer Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = 'cpe:/a:pango:pango';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900644");
  script_version("$Revision: 5122 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-27 13:16:00 +0100 (Fri, 27 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1194");
  script_bugtraq_id(34870);
  script_name("Pango Integer Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_pango_detect.nasl");
  script_mandatory_keys("Pango/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35018");
  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1798");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/05/07/1");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code via
  a long glyph string, and can cause denial of service.

  Impact Level: Application");
  script_tag(name:"affected", value:"Pango version prior to 1.24.0");
  script_tag(name:"insight", value:"Error in pango_glyph_string_set_size function in pango/glyphstring.c file,
  which fails to perform adequate boundary checks on user-supplied data before
  using the data to allocate memory buffers.");
  script_tag(name:"solution", value:"Upgrade to pango version 1.24.0 or later
  http://ftp.acc.umu.se/pub/GNOME/sources/pango/");
  script_tag(name:"summary", value:"This host has installed with Pango and is prone to Integer Buffer
  Overflow vulnerability");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_is_less(version:ver, test_version:"1.24.0")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.24.0");
  security_message(data:report);
  exit(0);
}

exit(99);