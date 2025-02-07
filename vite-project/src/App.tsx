import {TimeLine} from './TimeLine.tsx'
import './App.css'
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {

  return (
    <BrowserRouter>
		<Routes>
			<Route path="/" element={<TimeLine />} />
		</Routes>
	</BrowserRouter>
  )
}

export default App
