###############################################################################
# Openvas Vulnerability Test
# $id: secpod_arora_cn_ssl_cert_spoofing_vuln_lin.nasl 2011-12-15 14:01:47z dec $
#
# Arora Common Name SSL Certificate Spoofing Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to spoof the
common name (CN) of a certificate via rich text.

Impact Level: Application.";

tag_affected = "Arora version 0.11 and prior";

tag_insight = "The flaw is due to not using a certain font when rendering
certificate fields in a security dialog.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Arora and is prone common name SSL
certificate spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902764");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3367");
  script_bugtraq_id(49925);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-15 14:01:47 +0530 (Thu, 15 Dec 2011)");
  script_name("Arora Common Name SSL Certificate Spoofing Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46269");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520041");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=746875");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2011-10/att-0353/NDSA20111003.txt.asc");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("[0]\\.[0-9][0-9]\\.[0-9]");

## Getting arora file path
modName = find_file(file_name:"arora", file_path:"/usr/bin/",
                      useregex:TRUE, regexpar:"$", sock:sock);
arg = NULL;
foreach binaryName (modName)
{
  binaryName = chomp(binaryName);
  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) +
          garg[3] + raw_string(0x22) + " " + binaryName;
}

if(arg != NULL)
{
  arrVer = NULL;

  ## Grep the version
  arrVer = get_bin_version(full_prog_name:grep, version_argv:arg,
                              ver_pattern:"([0-9.]+)", sock:sock);
  if(arrVer[0] != NULL)
  {
    ## Check the arora version
    if(version_is_less_equal(version:arrVer[0], test_version:"0.11.0")){
      security_message(0);
    }
  }
}
close(sock);
ssh_close_connection();
