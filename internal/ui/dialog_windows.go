//go:build windows

package ui

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// logoPNGB64 es el isologo GDI (96x96 PNG, extraído de installer/firmadorgdi.ico)
// embebido para que los diálogos WPF lo muestren sin depender de archivos en
// disco: viaja por env (AGDI_LOGO_B64) y PowerShell lo decodifica a BitmapImage.
const logoPNGB64 = "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"

// ShowPINDialog muestra un diálogo WPF (via PowerShell) para ingresar el PIN.
func ShowPINDialog(info TokenInfo) (PINResult, error) {
	log.Printf("ShowPINDialog: iniciando via PowerShell — label=%q", info.Label)

	env := append(os.Environ(),
		"AGDI_LABEL="+sanitize(info.Label),
		"AGDI_MANUFACTURER="+sanitize(info.Manufacturer),
		"AGDI_CUIL="+sanitize(info.SerialNumber),
		"AGDI_VALID="+sanitize(info.ValidUntil),
		"AGDI_WRONG_PIN="+boolStr(info.WrongPIN),
		"AGDI_BATCH_COUNT="+strconv.Itoa(info.BatchCount),
		"AGDI_LOGO_B64="+logoPNGB64,
	)

	cmd := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", buildPSScript(),
	)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			log.Printf("ShowPINDialog: PowerShell exit=%d stderr=%q stdout=%q",
				exitErr.ExitCode(), stderrStr, strings.TrimSpace(string(out)))
			if exitErr.ExitCode() == 1 && stderrStr == "" {
				return PINResult{Cancelled: true}, ErrCancelled
			}
			return PINResult{Cancelled: true},
				fmt.Errorf("diálogo PIN falló (exit=%d): %s", exitErr.ExitCode(), stderrStr)
		}
		log.Printf("ShowPINDialog: error lanzando PowerShell: %v", err)
		return PINResult{Cancelled: true}, fmt.Errorf("no se pudo lanzar PowerShell: %w", err)
	}

	pin := strings.TrimSpace(string(out))
	if pin == "" {
		stderrStr := strings.TrimSpace(stderr.String())
		log.Printf("ShowPINDialog: output vacío (stderr=%q)", stderrStr)
		return PINResult{Cancelled: true},
			fmt.Errorf("diálogo PIN devolvió output vacío (stderr: %s)", stderrStr)
	}
	log.Printf("ShowPINDialog: PIN recibido (len=%d)", len(pin))
	return PINResult{PIN: pin}, nil
}

// ShowInfoDialog muestra un diálogo informativo WPF con tema GDI oscuro.
func ShowInfoDialog(title, message string) {
	runNotifyPS(title, message, false)
}

// ShowErrorDialog muestra un diálogo de error WPF con tema GDI oscuro.
func ShowErrorDialog(title, message string) {
	runNotifyPS(title, message, true)
}

func runNotifyPS(title, message string, isError bool) {
	env := append(os.Environ(),
		"AGDI_DLG_TITLE="+title,
		"AGDI_DLG_MSG="+message,
		"AGDI_DLG_ERROR="+boolStr(isError),
		"AGDI_LOGO_B64="+logoPNGB64,
	)
	cmd := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", buildNotifyScript(),
	)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		log.Printf("ShowInfoDialog/ErrorDialog PowerShell error: %v", err)
	}
}

// sanitize elimina bytes NUL y recorta espacios — los strings PKCS#11 son C fijos.
func sanitize(s string) string {
	return strings.TrimRight(strings.ReplaceAll(s, "\x00", ""), " ")
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func buildNotifyScript() string {
	return `
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$title   = $env:AGDI_DLG_TITLE
$msg     = $env:AGDI_DLG_MSG
$isError = $env:AGDI_DLG_ERROR -eq '1'

$icon   = if ($isError) { [char]0x2715 } else { [char]0x2713 }
$iconFg = if ($isError) { '#F87171' }    else { '#22C55E' }
$iconBg = if ($isError) { '#2D0A0A' }    else { '#052E16' }

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="FirmadorGDI"
        Width="400" SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        Background="#0F172A"
        FontFamily="Segoe UI">
  <Window.Resources>
    <Style x:Key="BtnPrimary" TargetType="Button">
      <Setter Property="Background" Value="#0EA5E9"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="32,10"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="5"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <Rectangle Grid.Row="0" Fill="#0EA5E9"/>
    <StackPanel Grid.Row="1" Margin="32,28,32,28" HorizontalAlignment="Center">
      <Border x:Name="iconBorder" Width="52" Height="52" CornerRadius="26"
              HorizontalAlignment="Center" Margin="0,0,0,20">
        <TextBlock x:Name="iconText" FontSize="24" FontWeight="Bold"
                   HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <TextBlock x:Name="titleText" Foreground="#F1F5F9" FontSize="18" FontWeight="Bold"
                 HorizontalAlignment="Center" Margin="0,0,0,12"
                 TextWrapping="Wrap" TextAlignment="Center"/>
      <TextBlock x:Name="msgText" Foreground="#94A3B8" FontSize="13"
                 HorizontalAlignment="Center" TextWrapping="Wrap" TextAlignment="Center"
                 MaxWidth="320" Margin="0,0,0,28"/>
      <Button x:Name="btnOK" Content="Aceptar" Style="{StaticResource BtnPrimary}"
              HorizontalAlignment="Center"/>
    </StackPanel>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$win    = [Windows.Markup.XamlReader]::Load($reader)

# Isologo GDI embebido (AGDI_LOGO_B64): icono de ventana + header. Soft-fail:
# un logo que no decodifica jamas puede impedir firmar.
if ($env:AGDI_LOGO_B64) {
    try {
        $logoBytes = [Convert]::FromBase64String($env:AGDI_LOGO_B64)
        $logoMs  = New-Object System.IO.MemoryStream(,$logoBytes)
        $logoBmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $logoBmp.BeginInit()
        $logoBmp.StreamSource = $logoMs
        $logoBmp.CacheOption  = 'OnLoad'
        $logoBmp.EndInit()
        $logoBmp.Freeze()
        $win.Icon = $logoBmp
        $imgLogo = $win.FindName('imgLogo')
        if ($imgLogo) { $imgLogo.Source = $logoBmp }
    } catch { }
}

$win.FindName('iconBorder').Background = [Windows.Media.SolidColorBrush][Windows.Media.ColorConverter]::ConvertFromString($iconBg)
$win.FindName('iconText').Text         = $icon
$win.FindName('iconText').Foreground   = [Windows.Media.SolidColorBrush][Windows.Media.ColorConverter]::ConvertFromString($iconFg)
$win.FindName('titleText').Text        = $title
$win.FindName('msgText').Text          = $msg

$btnOK = $win.FindName('btnOK')
$btnOK.Add_Click({ $win.Close() })
$win.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq 'Return' -or $e.Key -eq 'Escape') { $win.Close() }
})
$win.ShowDialog() | Out-Null
`
}

func buildPSScript() string {
	return `
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$label    = $env:AGDI_LABEL
$manuf    = $env:AGDI_MANUFACTURER
$cuil     = $env:AGDI_CUIL
$valid    = $env:AGDI_VALID
$wrongPin = $env:AGDI_WRONG_PIN -eq '1'
$batch    = 0
if ($env:AGDI_BATCH_COUNT) { $batch = [int]$env:AGDI_BATCH_COUNT }

$tokenLine = if ($manuf) { "$label  ·  $manuf" } else { $label }

$wrongPinXaml = ''
if ($wrongPin) {
    $wrongPinXaml = '<TextBlock Margin="0,0,0,12" Foreground="#F87171" FontSize="13">PIN incorrecto. Intentá de nuevo.</TextBlock>'
}

# GDI-167: con una tanda, el diálogo dice CUÁNTOS documentos se firman con este
# PIN. Sin eso el usuario estaría autorizando a ciegas.
$batchXaml = ''
if ($batch -gt 1) {
    $batchXaml = '<Border Background="#164E63" CornerRadius="8" Padding="16,12" Margin="0,0,0,20"><StackPanel><TextBlock Foreground="#67E8F9" FontSize="11" FontWeight="SemiBold" Text="FIRMA EN TANDA"/><TextBlock Foreground="#F1F5F9" FontSize="15" FontWeight="SemiBold" Margin="0,4,0,0">Vas a firmar ' + $batch + ' documentos</TextBlock><TextBlock Foreground="#A5F3FC" FontSize="12" TextWrapping="Wrap" Margin="0,4,0,0">Con un solo PIN. Si alguno falla, no queda ninguno firmado.</TextBlock></StackPanel></Border>'
}

$validLine = ''
if ($valid) {
    $validLine = '<TextBlock Foreground="#94A3B8" FontSize="12">Válido hasta ' + $valid + '</TextBlock>'
}

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="FirmadorGDI"
        Width="420" SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        Background="#0F172A"
        FontFamily="Segoe UI">
  <Window.Resources>
    <Style x:Key="PinBox" TargetType="PasswordBox">
      <Setter Property="Background" Value="#1E293B"/>
      <Setter Property="Foreground" Value="#F1F5F9"/>
      <Setter Property="BorderBrush" Value="#334155"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,10"/>
      <Setter Property="FontSize" Value="16"/>
      <Setter Property="CaretBrush" Value="#38BDF8"/>
    </Style>
    <Style x:Key="BtnPrimary" TargetType="Button">
      <Setter Property="Background" Value="#0EA5E9"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="24,10"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="BtnSecondary" TargetType="Button">
      <Setter Property="Background" Value="#1E293B"/>
      <Setter Property="Foreground" Value="#94A3B8"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="24,10"/>
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="6"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <Rectangle Grid.Row="0" Fill="#0EA5E9"/>
    <StackPanel Grid.Row="1" Margin="32,24,32,28">
      <StackPanel Orientation="Horizontal" Margin="0,0,0,24">
        <Image x:Name="imgLogo" Width="40" Height="40" Margin="0,0,12,0" VerticalAlignment="Center"/>
        <StackPanel VerticalAlignment="Center">
          <TextBlock Text="FirmadorGDI" Foreground="#F1F5F9" FontSize="20" FontWeight="Bold" Margin="0,0,0,2"/>
          <TextBlock Text="Firma digital con token físico" Foreground="#64748B" FontSize="12"/>
        </StackPanel>
      </StackPanel>
      <Border Background="#1E293B" CornerRadius="8" Padding="16,14" Margin="0,0,0,20">
        <StackPanel>
          <TextBlock Foreground="#94A3B8" FontSize="11" Text="TOKEN DETECTADO" FontWeight="SemiBold" Margin="0,0,0,6"/>
          <TextBlock Foreground="#F1F5F9" FontSize="14" FontWeight="SemiBold" TextWrapping="Wrap">$tokenLine</TextBlock>
          <TextBlock Foreground="#94A3B8" FontSize="13" Margin="0,4,0,0">CUIL: $cuil</TextBlock>
          $validLine
        </StackPanel>
      </Border>
      $batchXaml
      $wrongPinXaml
      <TextBlock Text="PIN del token" Foreground="#94A3B8" FontSize="12" FontWeight="SemiBold" Margin="0,0,0,8"/>
      <PasswordBox x:Name="txtPin" Style="{StaticResource PinBox}" Margin="0,0,0,24"/>
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="12"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Button x:Name="btnCancel" Grid.Column="0" Content="Cancelar" Style="{StaticResource BtnSecondary}"/>
        <Button x:Name="btnOK"     Grid.Column="2" Content="  Firmar  " Style="{StaticResource BtnPrimary}"/>
      </Grid>
    </StackPanel>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$win    = [Windows.Markup.XamlReader]::Load($reader)

# Isologo GDI embebido (AGDI_LOGO_B64): icono de ventana + header. Soft-fail:
# un logo que no decodifica jamas puede impedir firmar.
if ($env:AGDI_LOGO_B64) {
    try {
        $logoBytes = [Convert]::FromBase64String($env:AGDI_LOGO_B64)
        $logoMs  = New-Object System.IO.MemoryStream(,$logoBytes)
        $logoBmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $logoBmp.BeginInit()
        $logoBmp.StreamSource = $logoMs
        $logoBmp.CacheOption  = 'OnLoad'
        $logoBmp.EndInit()
        $logoBmp.Freeze()
        $win.Icon = $logoBmp
        $imgLogo = $win.FindName('imgLogo')
        if ($imgLogo) { $imgLogo.Source = $logoBmp }
    } catch { }
}

$txtPin   = $win.FindName('txtPin')
$btnOK    = $win.FindName('btnOK')
$btnCancel= $win.FindName('btnCancel')

$result = ''

$btnOK.Add_Click({
    if ($txtPin.Password -ne '') {
        $script:result = $txtPin.Password
        $win.Close()
    }
})

$btnCancel.Add_Click({ $win.Close() })

$win.Add_ContentRendered({ $txtPin.Focus() })

$win.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq 'Return' -and $txtPin.Password -ne '') {
        $script:result = $txtPin.Password
        $win.Close()
    }
    if ($e.Key -eq 'Escape') { $win.Close() }
})

$win.ShowDialog() | Out-Null

if ($script:result -ne '') {
    Write-Output $script:result
} else {
    exit 1
}
`
}
