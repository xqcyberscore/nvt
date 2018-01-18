###############################################################################
# Openvas Vulnerability Test
# $id: gb_mako_xss_vuln.nasl 10044 2010-07-12 13:10:35z jul $
#
# Description: Mako 'cgi.escape()' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the gnu general public license version 2
# (or any later version), as published by the free software foundation.
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site.
  Impact Level: Application.";
tag_affected = "Mako version before 0.3.4";

tag_insight = "The flaw exists due to an error in 'cgi.escape()' function which does not
  properly filter single quotes.";
tag_solution = "Upgrade to Mako version 0.3.4 or later,
  For updates refer to http://www.makotemplates.org/download.html";
tag_summary = "This host is installed with Mako and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801402");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2480");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mako 'cgi.escape()' Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://bugs.python.org/issue9061");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39935");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Check for the file mako-render
makoName = find_bin(prog_name:"mako-render", sock:sock);
foreach binaryName (makoName)
{
  ## Grep for the version
  makoVer = get_bin_version(full_prog_name:"cat", version_argv:binaryName,
                            ver_pattern:"Mako==([0-9.]+)", sock:sock);
  if(makoVer[1] != NULL)
  {
    ## Check for the Mako version less than 0.3.4
    if(version_is_less(version:makoVer[1], test_version:"0.3.4")){
      security_message(0);
    }
  }
}
ssh_close_connection();
