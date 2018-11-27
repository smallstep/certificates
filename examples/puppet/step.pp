# smallstep package configuration
class step(
  $version = false,
) {
  if !$version {
    fail("class ${name}: version cannot be empty")
  }

  $pkg = "step_${version}_linux_amd64.tar.gz"
  $download_url = "https://github.com/smallstep/cli/releases/download/v${version}/step_${version}_linux_amd64.tar.gz"
  $step_exec = '/opt/smallstep/bin/step'

  exec {
    'download/update smallstep':
      command => "/usr/bin/curl --fail -o /tmp/${pkg} ${download_url} && /bin/tar -xzvf /tmp/${pkg} -C /opt",
      unless  => "/usr/bin/which ${step_exec} && ${step_exec} version | grep ${version}",
      user    => 'step',
      require => File['/opt/smallstep'];
  }

  file {
    '/opt/smallstep':
      ensure  => directory,
      mode    => '0755',
      owner   => 'step';
    '/usr/local/lib/step':
      ensure  => directory,
      mode    => '0755',
      owner   => 'step';
    '/usr/local/lib/step/.step':
      ensure  => directory,
      mode    => '0755',
      owner   => 'step';
    '/usr/local/lib/step/.step/secrets':
      ensure  => directory,
      mode    => '0644',
      owner   => 'step';
    '/usr/local/lib/step/.step/config':
      ensure  => directory,
      mode    => '0755',
      owner   => 'step';
  }

  group { 'step':
      ensure => present,
      gid    => $::step_id,
  }

  user { 'step':
      ensure     => present,
      gid        => 'puppet',
      home       => '/usr/local/lib/step',
      managehome => false,
      uid        => $::step_id,
  }
}
