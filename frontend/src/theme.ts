import { createTheme } from '@mui/material/styles'

export const theme = createTheme({
  cssVariables: { colorSchemeSelector: 'data-mui-color-scheme' },
  colorSchemes: {
    // Values mirror the --teal / --bg-* / --line / --ink tokens in styles.css. MUI needs
    // literal colors here so it can derive hover and alpha variants from them.
    light: {
      palette: {
        primary: { main: '#295F65', dark: '#1B484D' },
        secondary: { main: '#FF92EB' },
        background: { default: '#FFFFFF', paper: '#FEFDFC' },
        divider: '#E1E0DF',
        text: { primary: '#2A2826', secondary: '#605D5A' },
      },
    },
    dark: {
      palette: {
        primary: { main: '#41B7C2', dark: '#8FDCE3' },
        secondary: { main: '#FF92EB' },
        background: { default: '#1A1918', paper: '#211F1E' },
        divider: '#3A3835',
        text: { primary: '#F2EFEC', secondary: '#BAB5B1' },
      },
    },
  },
  typography: {
    fontFamily: "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
    h1: { fontFamily: "'Anybody', 'Inter', sans-serif", fontSize: '1.75rem', fontWeight: 600, letterSpacing: '-0.02em' },
    h2: { fontFamily: "'Anybody', 'Inter', sans-serif", fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.015em' },
    body1: { fontWeight: 450, letterSpacing: '0.001em' },
    body2: { fontWeight: 450, letterSpacing: '0.001em' },
  },
  shape: { borderRadius: 6 },
  components: {
    MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { textTransform: 'none', fontWeight: 600 } } },
    MuiTextField: { defaultProps: { fullWidth: true, size: 'small' } },
    MuiPaper: { styleOverrides: { root: { borderColor: 'var(--line)' } } },
    // size="small" only tightens padding; MUI still renders 16px body1 inside
    // inputs, selects, and menus. Match the 13px used everywhere else in the UI.
    MuiInputBase: { styleOverrides: { root: { fontSize: 13 }, input: { fontSize: 13 } } },
    MuiInputLabel: { styleOverrides: { root: { fontSize: 13 } } },
    MuiFormHelperText: { styleOverrides: { root: { fontSize: 11.5 } } },
    MuiSelect: { styleOverrides: { select: { fontSize: 13 } } },
    MuiMenuItem: { styleOverrides: { root: { fontSize: 13, minHeight: 32 } } },
    MuiAutocomplete: { styleOverrides: { option: { fontSize: 13, minHeight: 32 } } },
    MuiToggleButton: { styleOverrides: { root: { fontSize: 12, fontWeight: 500, textTransform: 'none' } } },
  },
})
