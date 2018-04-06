###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_etherape_rpc_call_parsing_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# EtherApe RPC Packet Processing Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows remote attackers to cause a NULL pointer
  dereference or cause a denial of service.
  Impact Level: Application";
tag_affected = "EtherApe version prior to 0.9.12";
tag_insight = "The flaw is due to an error in the add_conversation function in
  'conversations.c' when processing specially crafted RPC packet.";
tag_solution = "Upgrade to EtherApe version 0.9.12 or later,
  For updates refer to http://etherape.sourceforge.net/";
tag_summary = "This host is installed with EtherApe and is prone to denial of
  service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802340");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3369");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-08 17:22:20 +0530 (Tue, 08 Nov 2011)");
  script_name("EtherApe RPC Packet Processing Denial of Service Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45989");
  script_xref(name : "URL" , value : "http://etherape.sourceforge.net/NEWS.html");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/09/19/4");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/09/22/1");
  script_xref(name : "URL" , value : "http://sourceforge.net/tracker/?func=detail&aid=3309061&group_id=2712&atid=102712");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

etherapeName = find_file(file_name:"etherape", file_path:"/", useregex:TRUE,
                         regexpar:"$", sock:sock);

foreach binaryName (etherapeName)
{
  ## Get the EtherApe version from command
  etherVer = get_bin_version(full_prog_name:chomp(binaryName), version_argv:"--version",
                             ver_pattern:"GNOME EtherApe ([0-9.]+)", sock:sock);

  if(etherVer[1])
  {
    ## Check for EtherApe Version less than 0.9.12
    if(version_is_less(version:etherVer[1], test_version:"0.9.12"))
    {
      security_message(0);
      close(sock);
      exit(0);
    }
  }
}
close(sock);
