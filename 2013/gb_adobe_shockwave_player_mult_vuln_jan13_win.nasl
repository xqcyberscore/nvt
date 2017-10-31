###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln_jan13_win.nasl 7584 2017-10-26 12:15:30Z cfischer $
#
# Adobe Shockwave Player Multiple Vulnerabilities Jan-2013 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow an attacker to execute
arbitrary code by tricking a user into visiting a specially crafted document.

Impact Level: System/Application";

tag_affected = "Adobe Shockwave Player Versions 11.6.8.638 and prior on
Windows";

tag_insight = "
- An error in Xtras allows attackers to trigger installation of
  arbitrary signed Xtras via a Shockwave movie that contains an Xtra URL.
- An error exists when handling a specially crafted HTML document that calls
  Shockwave content via a compatibility parameter forcing application to
  downgrade to the insecure version.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Adobe Shockwave Player and is prone
to multiple vulnerabilities.";

if(description)
{
  script_id(803092);
  script_version("$Revision: 7584 $");
  script_cve_id("CVE-2012-6270", "CVE-2012-6271");
  script_bugtraq_id(56975, 56972);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 14:15:30 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-01-02 13:05:18 +0530 (Wed, 02 Jan 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities Jan-2013 (Windows)");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/546769");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/519137");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027903");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027905");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80712");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80713");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_require_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");
include("smb_nt.inc"); # For registry_key_exists() used in secpod_activex.inc
include("secpod_activex.inc");

## Variables Initialization
shockVer = NULL;

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

## Check for Adobe Shockwave Player versions  11.6.8.638 and prior
if(version_is_less_equal(version:shockVer, test_version:"11.6.8.638"))
{
  # Check if Kill-Bit is set for ActiveX control
  clsids = make_list("{166B1BCA-3F9C-11CF-8075-444553540000}",
                     "{233C1507-6A77-46A4-9443-F871F945D258}");

  ## check for each bit
  foreach clsid (clsids)
  {
    if(is_killbit_set(clsid:clsid) == 0)
    {
      security_message(0);
      exit(0);
    }
  }
}
