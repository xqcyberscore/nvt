###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_prdts_detect_lin.nasl 9064 2018-03-09 09:14:44Z cfischer $
#
# Multiple Java Products Version Detection (Linux)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800385");
  script_version("$Revision: 9064 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-09 10:14:44 +0100 (Fri, 09 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Multiple Java Products Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detection of installed version of Java products
  on Linux systems. It covers the following:

  - Sun Java

  - Oracle Java

  - IBM Java

  - GCJ

  The script logs in via ssh, searches for executables 'javaaws' and
  'java' and queries the found executables via command line option '-fullversion'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

# Check for Java Web Start
jwspaths = find_bin( prog_name:"javaws", sock:sock );
if( jwspaths ) {
  foreach executableFile( jwspaths ) {
    jwsVer = get_bin_version( full_prog_name:chomp(executableFile), sock:sock, version_argv:"-fullversion", ver_pattern:"Java\(TM\) Web Start ([0-9_.]+)" );
    if( ! isnull( jwsVer[1] ) ) {
      set_kb_item( name:"Java/WebStart/Linux/Ver", value:jwsVer[1] );
      register_and_report_cpe( app:"Java WebStart", ver:jwsVer[1], concluded:jwsVer[0], base:"cpe:/a:sun:java_web_start:", expr:"^([0-9]\.[0-9_.]+)", insloc:executableFile );
    }
  }
}

# Check for Java JRE
javapaths = find_bin( prog_name:"java", sock:sock );
if( javapaths ) {
  foreach executableFile( javapaths ) {
    javaVer = get_bin_version( full_prog_name:chomp( executableFile ), sock:sock, version_argv:"-fullversion ", ver_pattern:'java.? full version \"(.*)\"' );
    # LibGCJ
    if( "gcj" >< javaVer[1] ) {
      gcjVer = eregmatch( pattern:"([0-9]\.[0-9_.]+)", string:javaVer[2] ); # TODO: This doesn't match the regex in get_bin_version above...
      if( ! isnull( gcjVer[1] ) ) {
        set_kb_item( name:"Java/JRE/Linux/LibGCJ/Ver", value:gcjVer[1] );
        log_message( data:'Detected Java JRE version: ' + gcjVer[1] + '\nLocation: ' + executableFile + '\n\nConcluded from version identification result:\n' + javaVer[max_index(javaVer)-1] );
      }
    }
    # IBM Java
    else if( "IBM" >< javaVer[1] ) {
      ibmVer = eregmatch( pattern:"([0-9]\.[0-9._]+).*(SR[0-9]+)", string:javaVer[1] );
      if( ibmVer[1] && ! isnull( ibmVer[2] ) ) {
        ibmVer = ibmVer[1] + "." + ibmVer[2];
        set_kb_item( name:"IBM/Java/JRE/Linux/Ver", value:ibmVer );
        log_message( data:'Detected IBM Java JRE version: ' + ibmVer + '\nLocation: ' + executableFile + '\n\nConcluded from version identification result:\n' + javaVer[max_index(javaVer)-1]);
      }
    }
    # Sun/Oracle Java
    else if( javaVer[1] =~ "([0-9]\.[0-9._]+)-([b0-9]+)" ) {

      jvVer    = ereg_replace( pattern:"_|-", string:javaVer[1], replace:"." );
      javaVer1 = eregmatch( pattern:"([0-9]+\.[0-9]+\.[0-9]+)(\.([0-9]+))?", string:jvVer );
      if( javaVer1[1] && javaVer1[3] ) {
        javaVer_or = javaVer1[1] + ":update_" + javaVer1[3];
      } else if( javaVer1[1] ) {
        javaVer_or = javaVer1[1];
      }

      if( version_is_less( version:jvVer, test_version:"1.4.2.38" ) ||
          version_in_range( version:jvVer, test_version:"1.5", test_version2:"1.5.0.33" ) ||
          version_in_range( version:jvVer, test_version:"1.6", test_version2:"1.6.0.18" ) ) {
        java_name = "Sun Java";
        cpe = build_cpe( value:javaVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jre:" );
        if( isnull( cpe ) )
          cpe = "cpe:/a:sun:jre";
      } else {
        java_name = "Oracle Java";
        cpe = build_cpe( value:javaVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jre:" );
        if( isnull( cpe ) )
          cpe = "cpe:/a:oracle:jre";
      }

      set_kb_item( name:"Sun/Java/JRE/Linux/Ver", value:javaVer[1] );
      set_kb_item( name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE );
      register_and_report_cpe( app:java_name, ver:javaVer[1], concluded:javaVer[0], cpename:cpe, insloc:executableFile );
    }
  }
}

ssh_close_connection();
