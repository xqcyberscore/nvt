###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_prdts_detect_lin.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Sun Java Products Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-21
# Revsied to comply with Change Request #57.
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "Detection of installed version of Java products
on Linux systems. It covers Sun Java, IBM Java and GCJ.

The script logs in via ssh, searches for executables 'javaaws' and
'java' and queries the found executables via command line option '-fullversion'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800385";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5499 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Sun Java Products Version Detection (Linux)");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/Linux");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

function register_cpe(tmpVers, tmpExpr, tmpBase, binFile){
  local_var cpe;
  cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
  if(!isnull(cpe))
    register_product(cpe:cpe, location:binFile, nvt:SCRIPT_OID);
}

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

# Check for Java Web Start
jwspaths = find_bin(prog_name:"javaws", sock:sock);
if(jwspaths)
{
  foreach executableFile (jwspaths)
  {
    jwsVer = get_bin_version(full_prog_name:chomp(executableFile), sock:sock,
                             version_argv:"-fullversion",
                             ver_pattern:"Java\(TM\) Web Start ([0-9_.]+)");
    if(jwsVer[1] != NULL)
    {
      set_kb_item(name:"Java/WebStart/Linux/Ver", value:jwsVer[1]);
      log_message(data:'Detected Java WebStart version: ' + jwsVer[1] +
        '\nLocation: ' + executableFile +
        '\n\nConcluded from version identification result:\n' + jwsVer[max_index(jwsVer)-1]);

      register_cpe(tmpVers:jwsVer[1], tmpExpr:"^([0-9]\.[0-9_.]+)",
                   tmpBase:"cpe:/a:sun:java_web_start:", binFile:executableFile);
    }
  }
}

# Check for Java JRE
javapaths = find_bin(prog_name:"java", sock:sock);
if(javapaths)
{
  foreach executableFile (javapaths)
  {
    javaVer = get_bin_version(full_prog_name:chomp(executableFile), sock:sock,
                              version_argv:"-fullversion ",
                              ver_pattern:'java.? full version \"(.*)\"');
    # LibGCJ
    if("gcj" >< javaVer[1])
    {
      gcjVer = eregmatch(pattern:"([0-9]\.[0-9_.]+)", string:javaVer[2]);
      if(gcjVer[1] != NULL)
      {
        set_kb_item(name:"Java/JRE/Linux/LibGCJ/Ver", value:gcjVer[1]);
        log_message(data:'Detected Java JRE version: ' + gcjVer[1] +
          '\nLocation: ' + executableFile +
          '\n\nConcluded from version identification result:\n' +
          javaVer[max_index(javaVer)-1]);
      }
    }
    # IBM Java
    else if("IBM" >< javaVer[1]){
      ibmVer = eregmatch(pattern:"([0-9]\.[0-9._]+).*(SR[0-9]+)", string:javaVer[1]);
      if((ibmVer[1] && ibmVer[2]) != NULL)
      {
        ibmVer = ibmVer[1] + "." + ibmVer[2];
        set_kb_item(name:"IBM/Java/JRE/Linux/Ver", value:ibmVer);
        log_message(data:'Detected IBM Java JRE version: ' + ibmVer +
          '\nLocation: ' + executableFile +
          '\n\nConcluded from version identification result:\n' +
          javaVer[max_index(javaVer)-1]);
      }
    }
    # Sun Java
    else if(javaVer[1] =~ "([0-9]\.[0-9._]+)-([b0-9]+)")
    {
      set_kb_item(name:"Sun/Java/JRE/Linux/Ver", value:javaVer[1]);
      log_message(data:'Detected Sun Java JRE version: ' + javaVer[1] +
        '\nLocation: ' + executableFile +
        '\n\nConcluded from version identification result:\n' +
        javaVer[max_index(javaVer)-1]);
      register_cpe(tmpVers:javaVer[1], tmpExpr:"^([0-9._]+)", tmpBase:"cpe:/a:sun:jre:", binFile:executableFile);
    }
  }
}

ssh_close_connection();
