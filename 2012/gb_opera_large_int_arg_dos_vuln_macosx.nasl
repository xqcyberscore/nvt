###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_large_int_arg_dos_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Opera Large Integer Argument Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation may allow remote attackers to cause
a denial of service via a large integer argument.

Impact Level: Application";

tag_affected = "Opera version 11.60 and prior.";

tag_insight = "The flaw is due to an improper handling of argument sent to
the functions Int32Array, Float32Array, Float64Array, Uint32Array, Int16Array
or ArrayBuffer, which can be exploited to crash the Opera via a large
integer argument to these functions.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Opera and is prone to denial of
service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802396");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1003");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-08 15:53:59 +0530 (Wed, 08 Feb 2012)");
  script_name("Opera Large Integer Argument Denial of Service Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73027");
  script_xref(name : "URL" , value : "http://blog.vulnhunt.com/index.php/2012/02/02/cal-2012-0004-opera-array-integer-overflow/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
operaVer = NULL;

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version < 11.60
if(version_is_less_equal(version:operaVer, test_version:"11.60")){
  security_message(0);
}
